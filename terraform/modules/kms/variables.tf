variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "environment" {
  description = "Environment"
  type        = string
}

variable "common_tags" {
  description = "Common tags"
  type        = map(string)
}

variable "alias" {
  description = "Alias for the Lambda function"
  type        = string
}