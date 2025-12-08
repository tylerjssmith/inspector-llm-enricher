##### sns.tf ##################################################################
resource "aws_sns_topic" "inspector_alerts" {
  name = "${var.project_name}-inspector-alerts"
}

resource "aws_sns_topic_subscription" "inspector_email" {
  topic_arn = aws_sns_topic.inspector_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

