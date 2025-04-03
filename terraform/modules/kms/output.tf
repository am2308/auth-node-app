
output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

output "kms_key_id" {
  description = "The ID of the created KMS key"
  value       = aws_kms_key.this.id
}
