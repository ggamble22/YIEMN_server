# DynamoDB table + least-privilege IAM role for the service (IRSA).
#   terraform init && terraform apply -var oidc_provider_arn=... -var oidc_provider_url=...

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "table_name" {
  type    = string
  default = "auth"
}

variable "photo_bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name for user photo icons"
}

variable "oidc_provider_arn" {
  type        = string
  description = "EKS cluster OIDC provider ARN"
}

variable "oidc_provider_url" {
  type        = string
  description = "EKS OIDC issuer URL without https:// (e.g. oidc.eks.us-east-1.amazonaws.com/id/ABC123)"
}

provider "aws" {
  region = var.region
}

resource "aws_dynamodb_table" "auth" {
  name         = var.table_name
  billing_mode = "PAY_PER_REQUEST" # scales automatically; no capacity planning
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  deletion_protection_enabled = true

  tags = { service = "auth-service" }
}

# ---- user photo icons ----
# Private bucket: photos are served through the service's /v1/photos path
# (put CloudFront in front of that path), never directly from S3.
resource "aws_s3_bucket" "photos" {
  bucket = var.photo_bucket_name
  tags   = { service = "auth-service" }
}

resource "aws_s3_bucket_public_access_block" "photos" {
  bucket                  = aws_s3_bucket.photos.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "photos" {
  bucket = aws_s3_bucket.photos.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "photos" {
  bucket = aws_s3_bucket.photos.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:auth:auth-service"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "auth_service" {
  name               = "auth-service"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "dynamodb" {
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
      "dynamodb:BatchWriteItem",
      "dynamodb:ConditionCheckItem",
    ]
    resources = [aws_dynamodb_table.auth.arn]
  }
}

data "aws_iam_policy_document" "photos" {
  statement {
    actions   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.photos.arn}/avatars/*"]
  }
  statement {
    # Needed so a missing key returns NoSuchKey (404) instead of AccessDenied.
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.photos.arn]
  }
  statement {
    actions   = ["rekognition:DetectModerationLabels"]
    resources = ["*"] # this action has no resource-level permissions
  }
}

resource "aws_iam_role_policy" "photos" {
  name   = "photo-icons"
  role   = aws_iam_role.auth_service.id
  policy = data.aws_iam_policy_document.photos.json
}

resource "aws_iam_role_policy" "auth_service" {
  name   = "dynamodb-auth-table"
  role   = aws_iam_role.auth_service.id
  policy = data.aws_iam_policy_document.dynamodb.json
}

output "table_arn" {
  value = aws_dynamodb_table.auth.arn
}

output "photo_bucket" {
  value = aws_s3_bucket.photos.bucket
}

output "service_role_arn" {
  description = "Put this in k8s/serviceaccount.yaml"
  value       = aws_iam_role.auth_service.arn
}
