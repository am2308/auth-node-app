# This resource defines an AWS WAFv2 Web ACL
resource "aws_wafv2_web_acl" "waf_acl" {
  name        = var.waf_name
  description = "WAF for ALB"
  scope       = "REGIONAL" # Use "CLOUDFRONT" for CloudFront WAF
  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.waf_name
    sampled_requests_enabled   = true
  }

  dynamic "rule" {
    for_each = var.managed_rule_set
    content {
      name     = rule.value.name
      priority = rule.value.priority
      action {
        block {} # You can change this to "count" or "allow" if needed
      }
      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = rule.value.vendor_name
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }
  tags = var.common_tags
}




# This resource defines an AWS WAFv2 Web ACL association with an ALB
resource "aws_wafv2_web_acl_association" "waf_alb_association" {
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.waf_acl.arn
}