output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.findings.function_name
}

output "lambda_function_arn" {
  description = "Lambda function ARN"
  value       = aws_lambda_function.findings.arn
}

output "sns_topic_arn" {
  description = "SNS topic ARN"
  value       = aws_sns_topic.findings.arn
}

output "eventbridge_rule_name" {
  description = "EventBridge rule name"
  value       = aws_cloudwatch_event_rule.inspector2_findings.name
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.lambda.name
}
