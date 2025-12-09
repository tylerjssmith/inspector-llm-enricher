# lambda/sns_handler/sns_handler.py
import logging
import os
import json
import boto3

from typing import Any, Dict
from botocore.exceptions import ClientError
from call_llm import call_llm_for_finding
from build_email import build_email_subject, build_email_body

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

sns = boto3.client("sns")

def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    # Check Input
    if not SNS_TOPIC_ARN:
        logger.error("SNS_TOPIC_ARN environment variable is not set")
        raise RuntimeError("SNS_TOPIC_ARN environment variable is required")

    if event.get("source") != "aws.inspector2":
        logger.warning("Event source is not aws.inspector2, skipping")
        return {"statusCode": 200, "body": "Ignored non-Inspector2 event"}

    if event.get("detail-type") != "Inspector2 Finding":
        logger.warning("detail-type is not 'Inspector2 Finding', skipping")
        return {"statusCode": 200, "body": "Ignored non-finding event"}

    detail = event.get("detail", {}) or {}

    if detail.get("status") and detail["status"].upper() != "ACTIVE":
        logger.info("Finding status is %s; skipping notification", detail.get("status"))
        return {"statusCode": 200, "body": "No notification for non-ACTIVE finding"}

    # Call LLM; Build Email
    llm_result = call_llm_for_finding(event)
    subject    = build_email_subject(detail)
    message    = build_email_body(event, llm_result)

    # Send Email
    try:
        resp = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message,
        )
        logger.info("Published message to SNS: %s", resp.get("MessageId"))
        
    except ClientError as exc:
        logger.exception("Failed to publish message to SNS: %s", exc)
        raise

    # Return Status
    return {
        "statusCode": 200,
        "body": json.dumps(
            {"message": "Notification sent", "sns_message_id": resp.get("MessageId")}
        ),
    }
