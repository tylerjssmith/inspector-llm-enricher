# --- SNS Topic ---------------------------------------------------------------
resource "aws_sns_topic" "findings" {
  name = "${var.project_name}-notifications"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.findings.arn
  protocol  = "email"
  endpoint  = var.email_address
}


# --- IAM Role ----------------------------------------------------------------
resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# CloudWatch Logs
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Bedrock
resource "aws_iam_role_policy" "bedrock" {
  name = "${var.project_name}-bedrock-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = "arn:aws:bedrock:${var.aws_region}::foundation-model/${var.bedrock_model_id}"
      }
    ]
  })
}

# SNS Publish
resource "aws_iam_role_policy" "sns" {
  name = "${var.project_name}-sns-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.findings.arn
      }
    ]
  })
}


# --- CloudWatch Log Group ----------------------------------------------------
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.project_name}"
  retention_in_days = 30
}


# --- Lambda Function ---------------------------------------------------------
resource "aws_lambda_function" "findings" {
  function_name = var.project_name
  role          = aws_iam_role.lambda.arn
  runtime       = var.lambda_runtime
  handler       = "lambda_function.lambda_handler"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  # Placeholder — code deployed separately
  filename      = "../config/placeholder.zip"

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.findings.arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy_attachment.lambda_basic
  ]
}


# --- EventBridge Rule --------------------------------------------------------
resource "aws_cloudwatch_event_rule" "inspector2_findings" {
  name        = "${var.project_name}-rule"
  description = "Capture active Inspector2 findings"

  event_pattern = jsonencode({
    source      = ["aws.inspector2"]
    detail-type = ["Inspector2 Finding"]
    detail = {
      status   = ["ACTIVE"]
      type     = ["PACKAGE_VULNERABILITY"]
      severity = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.inspector2_findings.name
  target_id = "${var.project_name}-target"
  arn       = aws_lambda_function.findings.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.findings.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.inspector2_findings.arn
}
