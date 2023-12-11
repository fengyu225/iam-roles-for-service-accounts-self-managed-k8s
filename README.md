## Summary
This repo contains terraform files and bash commands for showing an example of setting up IAM Roles for Service Accounts (IRSA) with custom Kubernetes clusters.

## Step 1 - Infra Setup

Create VPC, subnets, IGW, Security Group, IAM role for testing, ASG for Kubernetes master and nodes

```shell
terraform apply
```

## Step 2 - Generate keypair for signing projected service account tokens

a new key pair for signing and verifying projected service account tokens. This can be done using the following `ssh-keygen` commands.

```shell
# Generate the keypair
PRIV_KEY="sa-signer.key"
PUB_KEY="sa-signer.key.pub"
PKCS_KEY="sa-signer-pkcs8.pub"

# generate a RSA2048 keypair
ssh-keygen -t rsa -b 2048 -f $PRIV_KEY -m pem
# convert the SSH pubkey to PKCS8
ssh-keygen -e -m PKCS8 -f $PUB_KEY > $PKCS_KEY
```

## Step 3 - Create public issuer for service account tokens

```shell
# Set environment variables for the region and bucket name
export AWS_REGION=us-east-1
export S3_BUCKET=oidc-test-$(cat /dev/random | LC_ALL=C tr -dc "[:lower:][:digit:]" | head -c 16)
# In this example the S3 bucket created is: oidc-test-icch7v3e3ckfzkwe

# Create the S3 bucket
aws s3api create-bucket --bucket $S3_BUCKET --region $AWS_REGION

# Set the hostname for the issuer
export HOSTNAME=s3.$AWS_REGION.amazonaws.com
export ISSUER_HOSTPATH=$HOSTNAME/$S3_BUCKET

# Create the OIDC discovery and keys documents
cat <<EOF > discovery.json
{
    "issuer": "https://$ISSUER_HOSTPATH",
    "jwks_uri": "https://$ISSUER_HOSTPATH/keys.json",
    "authorization_endpoint": "urn:kubernetes:programmatic_authorization",
    "response_types_supported": ["id_token"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "claims_supported": ["sub", "iss"]
}
EOF
```

```shell
git clone https://github.com/aws/amazon-eks-pod-identity-webhook.git
cd amazon-eks-pod-identity-webhook
```

```shell
# Generate the keys.json file
go run ./hack/self-hosted/main.go -key $PKCS_KEY | jq '.keys += [.keys[0]] | .keys[1].kid = ""' > keys.json
```

```shell
# Upload to S3
aws s3 cp ./discovery.json s3://$S3_BUCKET/.well-known/openid-configuration
aws s3 cp ./keys.json s3://$S3_BUCKET/keys.json

# make sure the discovery document and keys.json is public accessible

curl -L https://s3.us-east-1.amazonaws.com/oidc-test-icch7v3e3ckfzkwe/.well-known/openid-configuration
curl -L https://s3.us-east-1.amazonaws.com/oidc-test-icch7v3e3ckfzkwe/keys.json
```

## Step 4 - Create Kubernetes cluster

In this example we use kubekey to create Kubernetes cluster

```shell
mkdir -p /etc/kubernetes/pki
sudo cp sa-signer.key /etc/kubernetes/pki/sa.key
sudo cp sa-signer-pkcs8.pub /etc/kubernetes/pki/sa.pub
```

```shell
cat << EOF > config-sample.yaml
kind: Cluster
metadata:
  name: irsa-test
spec:
  hosts:
  - {name: node1, address: 192.168.0.199, internalAddress: 192.168.0.199, user: ubuntu, password: "0000"}
  - {name: node2, address: 192.168.0.216, internalAddress: 192.168.0.216, user: ubuntu, password: "0000"}
  - {name: node3, address: 192.168.0.235, internalAddress: 192.168.0.235, user: ubuntu, password: "0000"}
  roleGroups:
    etcd:
    - node1
    control-plane:
    - node1
    worker:
    - node2
    - node3
  controlPlaneEndpoint:
    domain: lb.kubesphere.local
    address: ""
    port: 6443
  kubernetes:
    clusterName: cluster.local
    apiServerArgs:
      - api-audiences=api
      - service-account-issuer=https://s3.us-east-1.amazonaws.com/oidc-test-icch7v3e3ckfzkwe
  network:
    plugin: calico
    kubePodsCIDR: 10.233.64.0/18
    kubeServiceCIDR: 10.233.0.0/18
    ## multus support. https://github.com/k8snetworkplumbingwg/multus-cni
    multusCNI:
      enabled: false
  registry:
    plainHTTP: false
    privateRegistry: ""
    namespaceOverride: ""
    registryMirrors: []
    insecureRegistries: []
  addons: []
EOF
```

Change the above IP to the internal IPs of Kubernetes master and workers created in Step 1

## Step 5 - Install **[amazon-eks-pod-identity-webhook](https://github.com/aws/amazon-eks-pod-identity-webhook/tree/master) (not used in this testing)**

First install cert-manager

```shell
helm repo add jetstack https://charts.jetstack.io --force-update

helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.9.0 \
  --set installCRDs=true

helm upgrade -i \
  cert-manager-csi-driver \
  jetstack/cert-manager-csi-driver \
  --namespace cert-manager \
  --wait
```

```shell
# under amazon-eks-pod-identity-webhook directory
make cluster-up IMAGE=amazon/amazon-eks-pod-identity-webhook:latest
```

## Step 6 - Create namespace, service account, pod for testing

Option 1 - without using amazon-eks-pod-identity-webhook

```shell
cat << EOF > test-irsa.yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: test-irsa
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: awscli-irsa-config
  namespace: test-irsa
data:
  AWS_DEFAULT_REGION: us-east-1
  AWS_ROLE_ARN: arn:aws:iam::072422391281:role/irsa_role
  AWS_WEB_IDENTITY_TOKEN_FILE: /var/run/secrets/oidc-iam/serviceaccount/token
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: awscli-sa
  namespace: test-irsa
---
apiVersion: v1
kind: Pod
metadata:
  name: awscli
  namespace: test-irsa
spec:
  containers:
    - image: amazon/aws-cli
      name: awscli
      command: ["sleep"]
      args: ["360000"]
      envFrom:
        - configMapRef:
            name: awscli-irsa-config
      volumeMounts:
        - mountPath: /var/run/secrets/oidc-iam/serviceaccount/
          name: aws-token
  serviceAccountName: awscli-sa
  volumes:
    - name: aws-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 600
              audience: api
EOF
```

```shell
kubectl apply -f test-irsa.yaml
```

Option 2 - Use webhook

```shell
cat << EOF > test-irsa-webhook.yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: test-irsa
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: awscli-sa
  namespace: test-irsa
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::072422391281:role/irsa_role"
    eks.amazonaws.com/audience: "api"
    eks.amazonaws.com/sts-regional-endpoints: "true"
    eks.amazonaws.com/token-expiration: "600"
---
apiVersion: v1
kind: Pod
metadata:
  name: awscli
  namespace: test-irsa
spec:
  containers:
    - image: amazon/aws-cli
      name: awscli
      command: ["sleep"]
      args: ["360000"]
  serviceAccountName: awscli-sa
EOF
```

More details about the pod created using option 2

```shell
ubuntu@node1:~$ kubectl describe pod -n test-irsa awscli
Name:         awscli
Namespace:    test-irsa
Priority:     0
Node:         node2/192.168.0.216
Start Time:   Mon, 11 Dec 2023 08:19:23 +0000
Labels:       <none>
Annotations:  cni.projectcalico.org/containerID: 667f4efda03e8fe9d0de032d739aac3b7d36fb800ad047d5ae272337859ffb0f
              cni.projectcalico.org/podIP: 10.233.96.9/32
              cni.projectcalico.org/podIPs: 10.233.96.9/32
Status:       Running
IP:           10.233.96.9
IPs:
  IP:  10.233.96.9
Containers:
  awscli:
    Container ID:  docker://91c7683307b8fecc421327b767100e07d8a899817607261ba3457483ded5923c
    Image:         amazon/aws-cli
    Image ID:      docker-pullable://amazon/aws-cli@sha256:e2a778146a45cb7cdcc55e3051c0de38ea9f180ed88383447f7ead6b0ba5e9a4
    Port:          <none>
    Host Port:     <none>
    Command:
      sleep
    Args:
      360000
    State:          Running
      Started:      Mon, 11 Dec 2023 08:19:24 +0000
    Ready:          True
    Restart Count:  0
    Environment:
      AWS_STS_REGIONAL_ENDPOINTS:   regional
      AWS_ROLE_ARN:                 arn:aws:iam::072422391281:role/irsa_role
      AWS_WEB_IDENTITY_TOKEN_FILE:  /var/run/secrets/eks.amazonaws.com/serviceaccount/token
    Mounts:
      /var/run/secrets/eks.amazonaws.com/serviceaccount from aws-iam-token (ro)
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-cwqpd (ro)
Conditions:
  Type              Status
  Initialized       True
  Ready             True
  ContainersReady   True
  PodScheduled      True
Volumes:
  aws-iam-token:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  3600
  kube-api-access-cwqpd:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  3607
    ConfigMapName:           kube-root-ca.crt
    ConfigMapOptional:       <nil>
    DownwardAPI:             true
QoS Class:                   BestEffort
Node-Selectors:              <none>
Tolerations:                 node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                             node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:
  Type    Reason     Age    From               Message
  ----    ------     ----   ----               -------
  Normal  Scheduled  5m17s  default-scheduler  Successfully assigned test-irsa/awscli to node2
  Normal  Pulling    5m16s  kubelet            Pulling image "amazon/aws-cli"
  Normal  Pulled     5m16s  kubelet            Successfully pulled image "amazon/aws-cli" in 136.254977ms
  Normal  Created    5m16s  kubelet            Created container awscli
  Normal  Started    5m16s  kubelet            Started container awscli
```

example token

```shell
{
  "aud": [
    "api"
  ],
  "exp": 1702286363,
  "iat": 1702282763,
  "iss": "https://s3.us-east-1.amazonaws.com/oidc-test-icch7v3e3ckfzkwe",
  "kubernetes.io": {
    "namespace": "test-irsa",
    "pod": {
      "name": "awscli",
      "uid": "48263ea3-527e-4c22-a555-457287077cba"
    },
    "serviceaccount": {
      "name": "awscli-sa",
      "uid": "07fe2bc3-d597-47c8-a57a-f0f9e1274cce"
    }
  },
  "nbf": 1702282763,
  "sub": "system:serviceaccount:test-irsa:awscli-sa"
}
```