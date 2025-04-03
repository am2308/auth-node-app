/*
 * This Terraform configuration defines an AWS Route 53 record of type "A" with an alias.
 * The record is created in the specified hosted zone and points to an Application Load Balancer (ALB).
 * The alias block specifies the ALB's DNS name and zone ID, and enables health evaluation for the target.
 */
resource "aws_route53_record" "alb_alias" {
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}
