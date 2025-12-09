# Function
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/sns_handler"
  output_path = "${path.module}/build/sns_handler.zip"
}

resource "aws_lambda_function" "inspector_finding_handler" {
  function_name = "inspector-finding-handler"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  role    = aws_iam_role.lambda_inspector_role.arn
  runtime = "python3.12"
  handler = "sns_handler.lambda_handler"
  timeout = 30

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.inspector_alerts.arn
      BEDROCK_MODEL_ID = var.model_name
    }
  }
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
      },

      # Bedrock
      {
        Effect = "Allow",
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ],
        Resource = "arn:aws:bedrock:${var.region_name}::foundation-model/${var.model_name}"
      }
    ]
  })
}