variable "project" {
  description = "Project name"
}

# environment name: production, staging, qa, dev
variable "env" {
  description = "Project environment"
}

variable "region" {
  default     = "eu-west-1"
  description = "AWS Region"
}

variable "vpc_cidr" {
  description = "CIDR Block for VPC"
}

variable "public_subnet_1_cidr" {
  description = "CIDR Block for Public Subnet 1"
}

variable "public_subnet_2_cidr" {
  description = "CIDR Block for Public Subnet 2"
}

variable "private_subnet_1_cidr" {
  description = "CIDR Block for Private Subnet 1"
}

variable "private_subnet_2_cidr" {
  description = "CIDR Block for Private Subnet 2"
}

variable "common_tags" {
  description = "Common tags"
  type        = map(string)
}

variable "s3_bucket_arn" {
  description = "log bucket arn"
  type        = string
}