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

# Bedrock
variable "model_name" {
  description = "Bedrock model ID"
  type        = string
  default     = "anthropic.claude-3-5-sonnet-20241022-v2:0"
}