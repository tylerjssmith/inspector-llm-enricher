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