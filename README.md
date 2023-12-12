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
In this example we use nginx to host the issuer

```shell
# Set environment variables for the region and bucket name
export AWS_REGION=us-east-1

# Set the hostname for the issuer
export ISSUER_HOSTPATH=k8s-idp.yufeng.live

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
cat << EOF > /etc/nginx/sites-enabled/idp.conf
server {
    listen 9999;

    # Health endpoint returning HTTP 200
    location /health {
        add_header Content-Type text/plain;
        return 200 'OK';
    }

    # Endpoint for .well-known/openid-configuration
    location /.well-known/openid-configuration {
        default_type application/json;
        alias /home/ubuntu/discovery.json;
    }

    # Endpoint for keys.json
    location /keys.json {
        default_type application/json;
        alias /home/ubuntu/keys.json;
    }
}
EOF

# make sure /home/ubuntu/keys.json and /home/ubuntu/discovery.json exist and are readable by nginx
```

```shell
sudo systemctl restart nginx
```

## Step 4 - Create Kubernetes cluster

In this example we use kubekey to create Kubernetes cluster

```shell
sudo passwd ubuntu # set password 0000 for user ubuntu
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

Install Kubekey
```shell
curl -sfL https://get-kk.kubesphere.io | VERSION=v2.0.0 sh -
```

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
      - service-account-issuer=https://k8s-idp.yufeng.live
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

## Step 5 - Install **[amazon-eks-pod-identity-webhook](https://github.com/aws/amazon-eks-pod-identity-webhook/tree/master)**

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
  name: awscli-irsa-config-custom-idp
  namespace: test-irsa
data:
  AWS_DEFAULT_REGION: us-east-1
  AWS_ROLE_ARN: arn:aws:iam::072422391281:role/irsa_role_custom_idp
  AWS_WEB_IDENTITY_TOKEN_FILE: /var/run/secrets/oidc-iam/serviceaccount/token
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: awscli-sa-custom-idp
  namespace: test-irsa
---
apiVersion: v1
kind: Pod
metadata:
  name: awscli-custom-idp
  namespace: test-irsa
spec:
  containers:
    - image: amazon/aws-cli
      name: awscli
      command: ["sleep"]
      args: ["360000"]
      envFrom:
        - configMapRef:
            name: awscli-irsa-config-custom-idp
      volumeMounts:
        - mountPath: /var/run/secrets/oidc-iam/serviceaccount/
          name: aws-token-custom-idp
  serviceAccountName: awscli-sa-custom-idp
  volumes:
    - name: aws-token-custom-idp
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
  name: awscli-sa-custom-idp
  namespace: test-irsa
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::072422391281:role/irsa_role_custom_idp"
    eks.amazonaws.com/audience: "api"
    eks.amazonaws.com/sts-regional-endpoints: "true"
    eks.amazonaws.com/token-expiration: "600"
---
apiVersion: v1
kind: Pod
metadata:
  name: awscli-custom-idp
  namespace: test-irsa
spec:
  containers:
    - image: amazon/aws-cli
      name: awscli
      command: ["sleep"]
      args: ["360000"]
  serviceAccountName: awscli-sa-custom-idp
EOF
```

More details about the pod created using option 2

```shell
ubuntu@node1:~$ kubectl describe pod -n test-irsa awscli
Name:         awscli-custom-idp
Namespace:    test-irsa
Priority:     0
Node:         node2/192.168.0.22
Start Time:   Tue, 12 Dec 2023 19:15:02 +0000
Labels:       <none>
Annotations:  cni.projectcalico.org/containerID: 179bf403ef5e48a11e05d2a2f6f45b7c560b881e960512131a9a58016fd9e606
              cni.projectcalico.org/podIP: 10.233.96.6/32
              cni.projectcalico.org/podIPs: 10.233.96.6/32
Status:       Running
IP:           10.233.96.6
IPs:
  IP:  10.233.96.6
Containers:
  awscli:
    Container ID:  docker://df967431fa0fb1562374498585259711093112bf4b143e0fc6c381c6a074c08b
    Image:         amazon/aws-cli
    Image ID:      docker-pullable://amazon/aws-cli@sha256:e2a778146a45cb7cdcc55e3051c0de38ea9f180ed88383447f7ead6b0ba5e9a4
    Port:          <none>
    Host Port:     <none>
    Command:
      sleep
    Args:
      360000
    State:          Running
      Started:      Tue, 12 Dec 2023 19:15:18 +0000
    Ready:          True
    Restart Count:  0
    Environment Variables from:
      awscli-irsa-config-custom-idp  ConfigMap  Optional: false
    Environment:                     <none>
    Mounts:
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-bp8ln (ro)
      /var/run/secrets/oidc-iam/serviceaccount/ from aws-token-custom-idp (rw)
Conditions:
  Type              Status
  Initialized       True
  Ready             True
  ContainersReady   True
  PodScheduled      True
Volumes:
  aws-token-custom-idp:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  600
  kube-api-access-bp8ln:
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
  Normal  Scheduled  9m21s  default-scheduler  Successfully assigned test-irsa/awscli-custom-idp to node2
  Normal  Pulling    9m20s  kubelet            Pulling image "amazon/aws-cli"
  Normal  Pulled     9m9s   kubelet            Successfully pulled image "amazon/aws-cli" in 11.002877302s
  Normal  Created    9m5s   kubelet            Created container awscli
  Normal  Started    9m5s   kubelet            Started container awscli
```

example token

```shell
{
  "aud": [
    "api"
  ],
  "exp": 1702409102,
  "iat": 1702408502,
  "iss": "https://k8s-idp.yufeng.live",
  "kubernetes.io": {
    "namespace": "test-irsa",
    "pod": {
      "name": "awscli-custom-idp",
      "uid": "681e08cb-3525-4f41-8708-6fb618e9996c"
    },
    "serviceaccount": {
      "name": "awscli-sa-custom-idp",
      "uid": "6ebf7c83-01d5-4057-8e7a-9ceb821ccbf2"
    }
  },
  "nbf": 1702408502,
  "sub": "system:serviceaccount:test-irsa:awscli-sa-custom-idp"
}
```

## Step 7 - Test

Inside the pod
```shell
bash-4.2# aws sts get-caller-identity
{
    "UserId": "AROARBXFV7XY6SVWRMB4M:botocore-session-1702408752",
    "Account": "072422391281",
    "Arn": "arn:aws:sts::072422391281:assumed-role/irsa_role_custom_idp/botocore-session-1702408752"
}
```

Access logs for requests from AWS STS for the OIDC discovery and keys documents
```shell
192.168.0.199 - - [12/Dec/2023:19:19:12 +0000] "GET /.well-known/openid-configuration HTTP/1.1" 200 365 "-" "AWS Security Token Service"
192.168.0.199 - - [12/Dec/2023:19:19:12 +0000] "GET /keys.json HTTP/1.1" 200 996 "-" "AWS Security Token Service"
```