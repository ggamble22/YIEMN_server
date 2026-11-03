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

resource "aws_iam_role_policy" "auth_service" {
  name   = "dynamodb-auth-table"
  role   = aws_iam_role.auth_service.id
  policy = data.aws_iam_policy_document.dynamodb.json
}

output "table_arn" {
  value = aws_dynamodb_table.auth.arn
}

output "service_role_arn" {
  description = "Put this in k8s/serviceaccount.yaml"
  value       = aws_iam_role.auth_service.arn
}
