# ================================================
# VPC
# ================================================
resource "aws_vpc" "main" {
  cidr_block           = "192.168.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "Kubernetes-VPC"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "192.168.0.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

resource "aws_route_table_association" "public_rt_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# ================================================
# Security Group
# ================================================
resource "aws_security_group" "k8s_sg" {
  name        = "k8s-sg"
  description = "Security group for Kubernetes"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group_rule" "k8s_master_egress_all" {
  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = aws_security_group.k8s_sg.id
}

resource "aws_security_group_rule" "k8s_master_ingress_internal" {
  type        = "ingress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = [aws_vpc.main.cidr_block]

  security_group_id = aws_security_group.k8s_sg.id
}

resource "aws_security_group_rule" "k8s_master_ingress_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = aws_security_group.k8s_sg.id
}

resource "aws_security_group_rule" "k8s_master_ingress_k8s_all" {
  type      = "ingress"
  from_port = 0
  to_port   = 0
  protocol  = "-1"

  source_security_group_id = aws_security_group.k8s_sg.id
  security_group_id        = aws_security_group.k8s_sg.id
}

# ================================================
# Kubernetes Master Nodes ASG
# ================================================
resource "aws_iam_role" "k8s_master_nodes" {
  name               = "k8s_master_nodes"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "k8s_master_nodes_policy" {
  name        = "k8s_master_nodes_policy"
  description = "Policy for Kubernetes Master Nodes"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AssociateAddress",
        "ec2:DescribeAddresses",
        "ec2:DescribeInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "k8s_master_nodes" {
  role       = aws_iam_role.k8s_master_nodes.name
  policy_arn = aws_iam_policy.k8s_master_nodes_policy.arn
}

resource "aws_iam_instance_profile" "k8s_master_nodes_instance_profile" {
  name = "k8s_master_nodes_instance_profile"
  role = aws_iam_role.k8s_master_nodes.name
}

resource "aws_launch_configuration" "k8s_master" {
  name_prefix          = "k8s-master-"
  image_id             = "ami-0fc5d935ebf8bc3bc"
  instance_type        = "t2.medium"
  iam_instance_profile = aws_iam_instance_profile.k8s_master_nodes_instance_profile.name
  security_groups      = [aws_security_group.k8s_sg.id]
  key_name             = "yu-feng-uf-1"
  user_data            = file("master-user-data.sh")
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "k8s_master" {
  name                      = "k8s-master-asg"
  launch_configuration      = aws_launch_configuration.k8s_master.id
  min_size                  = 1
  max_size                  = 1
  desired_capacity          = 1
  vpc_zone_identifier       = [aws_subnet.public_subnet.id]
  health_check_type         = "EC2"
  health_check_grace_period = 300
  tag {
    key                 = "Name"
    value               = "k8s-master"
    propagate_at_launch = true
  }
}

# ================================================
# Kubernetes Worker Nodes ASG
# ================================================
resource "aws_iam_role" "k8s_worker_nodes" {
  name               = "k8s_worker_nodes"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "k8s_worker_nodes_policy" {
  name        = "k8s_worker_nodes_policy"
  description = "Policy for Kubernetes Worker Nodes"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AssociateAddress",
        "ec2:DescribeAddresses",
        "ec2:DescribeInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "k8s_worker_nodes_attach" {
  role       = aws_iam_role.k8s_worker_nodes.name
  policy_arn = aws_iam_policy.k8s_worker_nodes_policy.arn
}


resource "aws_iam_instance_profile" "k8s_worker_nodes_instance_profile" {
  name = "k8s_worker_nodes_instance_profile"
  role = aws_iam_role.k8s_worker_nodes.name
}

resource "aws_launch_configuration" "k8s_worker" {
  name_prefix          = "k8s-worker-"
  image_id             = "ami-0fc5d935ebf8bc3bc"
  instance_type        = "t2.medium"
  iam_instance_profile = aws_iam_instance_profile.k8s_worker_nodes_instance_profile.name
  security_groups      = [aws_security_group.k8s_sg.id]
  key_name             = "yu-feng-uf-1"
  user_data            = file("worker-user-data.sh")
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "k8s_worker" {
  name                      = "k8s-worker-asg"
  launch_configuration      = aws_launch_configuration.k8s_worker.id
  min_size                  = 2
  max_size                  = 2
  desired_capacity          = 2
  vpc_zone_identifier       = [aws_subnet.public_subnet.id]
  health_check_type         = "EC2"
  health_check_grace_period = 300
  tag {
    key                 = "Name"
    value               = "k8s-worker"
    propagate_at_launch = true
  }
}

# ================================================
# IAM role for testing IAM Roles For Service Accounts
# ================================================
resource "aws_iam_role" "irsa_role" {
  name = "irsa_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Federated = aws_iam_openid_connect_provider.oidc.arn
        }
        Condition = {
          StringEquals = {
            "s3.us-east-1.amazonaws.com/oidc-test-icch7v3e3ckfzkwe:aud" : "api",
            "s3.us-east-1.amazonaws.com/oidc-test-icch7v3e3ckfzkwe:sub": "system:serviceaccount:test-irsa:awscli-sa",
          }
        }
      },
    ]
  })
}

resource "aws_iam_policy" "irsa_policy" {
  name        = "irsa_policy"
  description = "Policy for irsa_role"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        Effect = "Allow",
        Resource = [
          "arn:aws:s3:::test-bucket-21151",
          "arn:aws:s3:::test-bucket-21151/home/test/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "roles_anywhere_attach" {
  role       = aws_iam_role.irsa_role.name
  policy_arn = aws_iam_policy.irsa_policy.arn
}

resource "aws_iam_openid_connect_provider" "oidc" {
  url             = "https://s3.us-east-1.amazonaws.com/oidc-test-icch7v3e3ckfzkwe"
  client_id_list  = ["api"]
  # the thumbprint_list is used to list the certificate thumbprints that AWS IAM should trust when communicating with OIDC provider
  thumbprint_list = ["a60a22e15635ed0d1d4699794d1707701fee1db6"]
}