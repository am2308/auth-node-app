output "log_bucket_arn" {
  value = aws_s3_bucket.log_bucket.arn
}

output "log_bucket_id" {
  value = aws_s3_bucket.log_bucket.id
}