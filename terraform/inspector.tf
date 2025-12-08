##### variables.tf ############################################################
# Project Name
variable "project_name" {
  description = "project name used for tagging and naming"
  type        = string
  default     = "rainydaypolitics"
}

# Region
variable "region_name" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "alert_email" {
  description = "email address to receive Inspector alerts"
  type        = string
  default     = "rainydaypoliticswebsite@gmail.com"
}

##### providers.tf ############################################################
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.18"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0"
    }
  }
}

provider "aws" {
  region = var.region_name
  default_tags {
    tags = {
      Project   = var.project_name
      ManagedBy = "terraform"
    }
  }
}

##### lambda.tf ###############################################################
# Function
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_handler.py"
  output_path = "${path.module}/build/lambda_handler.zip"
}

resource "aws_lambda_function" "inspector_finding_handler" {
  function_name = "inspector-finding-handler"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  role    = aws_iam_role.lambda_inspector_role.arn
  runtime = "python3.12"
  handler = "lambda_handler.lambda_handler"
  timeout = 30
}

# Role
resource "aws_iam_role" "lambda_inspector_role" {
  name = "lambda-inspector-findings-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_inspector_policy" {
  name = "lambda-inspector-findings-policy"
  role = aws_iam_role.lambda_inspector_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # CloudWatch Logs
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:*:*:*"
      },

      # SNS
      {
        Effect = "Allow",
        Action = [
          "sns:Publish"
        ],
        Resource = aws_sns_topic.inspector_alerts.arn
      }
    ]
  })
}

##### eventbridge.tf ##########################################################
# Event Pattern
resource "aws_cloudwatch_event_rule" "inspector_findings" {
  name        = "inspector-finding"
  description = "Trigger Lambda on new Amazon Inspector2 finding"

  event_pattern = jsonencode({
    "source"      : ["aws.inspector2"],
    "detail-type" : ["Inspector2 Finding"]
  })
}

# Target
resource "aws_cloudwatch_event_target" "inspector_lambda_target" {
  rule      = aws_cloudwatch_event_rule.inspector_findings.name
  target_id = "inspector-finding-to-lambda"
  arn       = aws_lambda_function.inspector_finding_handler.arn
}

# Permission
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridgeInspector2"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.inspector_finding_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.inspector_findings.arn
}

##### sns.tf ##################################################################
resource "aws_sns_topic" "inspector_alerts" {
  name = "${var.project_name}-inspector-alerts"
}

resource "aws_sns_topic_subscription" "inspector_email" {
  topic_arn = aws_sns_topic.inspector_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

