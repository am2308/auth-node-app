variable "domain_name" {
  description = "Domain name for the Route 53 hosted zone"
  type        = string
}

variable "hosted_zone_id" {
  description = "The ID of the Route 53 hosted zone"
  type        = string
}

variable "alb_dns_name" {
  description = "DNS name of the ALB"
  type        = string
}

variable "alb_zone_id" {
  description = "ALB Zone ID required for Route 53 alias"
  type        = string
}