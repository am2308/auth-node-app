// This Terraform configuration file defines resources for creating a Customer Managed KMS Key and an alias for it.
// The KMS Key is used for encrypting CloudWatch Logs and SNS messages.

// Resource: aws_kms_key
// Description: Creates a Customer Managed KMS Key with key rotation enabled and a deletion window of 30 days.
// - description: A description of the KMS Key.
// - enable_key_rotation: Enables automatic key rotation.
// - deletion_window_in_days: Specifies the number of days before the key is deleted after being scheduled for deletion.
// - policy: Defines the key policy in JSON format.
//   - Version: The version of the policy language.
//   - Statement: A list of policy statements.
//     - Sid: A unique identifier for the statement.
//     - Effect: The effect of the statement (Allow or Deny).
//     - Principal: The principal that is allowed or denied access.
//     - Action: The actions that are allowed or denied.
//     - Resource: The resources that the actions apply to.
// - tags: A map of tags to assign to the resource, including common tags and environment-specific tags.

// Resource: aws_kms_alias
// Description: Creates an alias for the KMS Key.
// - name: The name of the alias.
// - target_key_id: The ID of the KMS Key to associate with the alias.


resource "aws_kms_key" "this" {
  description             = "Customer Managed KMS Key for CloudWatch Logs & SNS"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "EnableRootAccountAccess",
        Effect    = "Allow",
        Principal = { "AWS" : "arn:aws:iam::${var.aws_account_id}:root" },
        Action    = "kms:*",
        Resource  = "*"
      },
      {
        Sid    = "AllowCloudWatchLogsEncryption",
        Effect = "Allow",
        Principal = {
          Service = "logs.${var.region}.amazonaws.com"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ],
        Resource = "*"
      },
      {
        Sid    = "AllowSNSEncryption",
        Effect = "Allow",
        Principal = {
          Service = "sns.amazonaws.com"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ],
        Resource = "*"
      }
    ]
  })
  tags = merge(var.common_tags, {
    Environment = var.environment
  })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.alias}"
  target_key_id = aws_kms_key.this.key_id
}