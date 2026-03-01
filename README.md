# Leverage AI for Vulnerability Management
## Overview
This project builds an AWS Lambda function to process Amazon Inspector vulnerability findings and deliver AI-generated remediation recommendations via email. Inspector findings are normalized and sanitized against a strict schema to mitigate prompt injection attacks before being passed to Claude via AWS Bedrock.Infrastructure is provisioned with Terraform.

## Architecture
Amazon Inspector continuously scans EC2 instances for new vulnerabilities. A new vulnerability finding triggers a Lambda function ([`src/lambda_handler.py`](src/lambda_function.py)) via EventBridge. Lambda functions call Claude via Bedrock. Recommendations from Claude are incorporated into emails delivered to security teams via SNS. AWS services were provisioned using Terraform (see [`terraform/`](terraform/)).

<p align="center">
<img src="docs/architecture.jpg" alt="AWS architecture for inspector-llm-enricher" width="550">
</p>
