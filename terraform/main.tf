terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random" }
  }
}

provider "aws" {
  region = "eu-north-1"
}

# Bucket names are globally unique across all of AWS, so we append a random suffix.
resource "random_id" "suffix" {
  byte_length = 4
}

# ---------------------------------------------------------
# FINDING 1: Publicly accessible S3 bucket
# CIS AWS Foundations | DORA Art. 9 (Protection and prevention)
# ---------------------------------------------------------

resource "aws_s3_bucket" "public_bucket" {
  bucket = "meridian-public-${random_id.suffix.hex}"

  tags = {
    Project     = "grc-self-lab"
    Intentional = "vulnerable"
  }
}

# AWS blocks public access by default. We disable those guardrails, which is exactly the misconfiguration the scanner should detect.
resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

output "public_bucket_name" {
  value = aws_s3_bucket.public_bucket.id
}
# ---------------------------------------------------------
# FINDING 2: IAM user with full admin, no MFA
# DORA Art. 9 | Violates least privilege
# ---------------------------------------------------------

resource "aws_iam_user" "overprivileged" {
  name = "meridian-ops-user"
  tags = { Intentional = "vulnerable" }
}

resource "aws_iam_user_policy_attachment" "admin" {
  user       = aws_iam_user.overprivileged.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ---------------------------------------------------------
# FINDING 3: Security group open to the internet on SSH
# DORA Art. 9 | CIS: no 0.0.0.0/0 to port 22
# ---------------------------------------------------------

resource "aws_security_group" "wide_open" {
  name        = "meridian-sg-open"
  description = "Intentionally permissive for lab purposes"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Intentional = "vulnerable" }
}

# ---------------------------------------------------------
# FINDING 4: Unencrypted EBS volume
# DORA Art. 9 | Encryption at rest
# ---------------------------------------------------------

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "eu-north-1a"
  size              = 1
  encrypted         = false

  tags = { Intentional = "vulnerable" }
}
