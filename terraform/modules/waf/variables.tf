variable "waf_name" {
  description = "Name of the WAF WebACL"
  type        = string
  default     = "my-waf-webacl"
}

variable "aws_region" {
  description = "AWS region for the WAF deployment"
  type        = string
}

variable "alb_arn" {
  description = "ALB to associate with waf"
  type        = string
}

variable "managed_rule_set" {
  description = "List of AWS managed rule groups"
  type = list(object({
    name        = string
    vendor_name = string
    priority    = number
  }))
  default = [
    {
      name        = "AWSManagedRulesCommonRuleSet"
      vendor_name = "AWS"
      priority    = 1
    },
    {
      name        = "AWSManagedRulesKnownBadInputsRuleSet"
      vendor_name = "AWS"
      priority    = 2
    },
    {
      name        = "AWSManagedRulesSQLiRuleSet"
      vendor_name = "AWS"
      priority    = 3
    },
    {
      name        = "AWSManagedRulesAdminProtectionRuleSet"
      vendor_name = "AWS"
      priority    = 4
    }
  ]
}

variable "common_tags" {
  description = "Common tags"
  type        = map(string)
}
