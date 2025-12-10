"""
Receives Amazon Inspector findings, calls functions to build emails
with LLM-enriched remediation recommendations, and sends emails to
vulnerability managers via SNS.
"""

import json
import logging
import os
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from build_email import build_email_body, build_email_subject
from call_llm import call_llm_for_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

sns = boto3.client("sns")

SNS_SUBJECT_MAX_LENGTH = 100


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for processing Amazon Inspector findings.
    
    Validates the incoming event, calls LLM for remediation recommendations,
    builds an email notification, and publishes to SNS.
    
    Args:
        event: EventBridge event from Amazon Inspector2
        context: Lambda context object
        
    Returns:
        Dictionary with statusCode and body
    """
    try:
        logger.info("Received event", extra={
            "source": event.get("source"),
            "detail_type": event.get("detail-type"),
            "account": event.get("account"),
            "region": event.get("region")
        })
        
        # Validate environment configuration
        if not SNS_TOPIC_ARN:
            logger.error("SNS_TOPIC_ARN environment variable is not set")
            raise RuntimeError("SNS_TOPIC_ARN environment variable is required")
        
        # Validate event source
        if event.get("source") != "aws.inspector2":
            logger.info("Skipping event: source is not aws.inspector2")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Ignored non-Inspector2 event"})
            }
        
        # Validate event type
        if event.get("detail-type") != "Inspector2 Finding":
            logger.info("Skipping event: detail-type is not 'Inspector2 Finding'")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Ignored non-finding event"})
            }
        
        # Validate event structure
        detail = event.get("detail")
        if not detail:
            logger.warning("Event is missing 'detail' field")
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Invalid event structure: missing detail"})
            }
        
        # Filter by finding status (only process active findings)
        status = detail.get("status", "").upper()
        if status and status != "ACTIVE":
            logger.info(f"Skipping finding with status: {status}")
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": f"No notification for non-ACTIVE finding",
                    "status": status
                })
            }
        
        # Check remaining execution time
        if context:
            remaining_time_ms = context.get_remaining_time_in_millis()
            if remaining_time_ms < 30000:  # Less than 30 seconds
                logger.warning(f"Insufficient time remaining: {remaining_time_ms}ms")
                raise TimeoutError("Lambda approaching timeout threshold")
        
        # Call LLM for remediation recommendations
        logger.info("Calling LLM for remediation recommendations")
        llm_result = call_llm_for_finding(event)
        
        # Build email notification
        logger.info("Building email notification")
        subject = build_email_subject(detail)
        message = build_email_body(event, llm_result)
        
        # Ensure subject fits SNS constraints
        if len(subject) > SNS_SUBJECT_MAX_LENGTH:
            subject = subject[:SNS_SUBJECT_MAX_LENGTH]
            logger.info(f"Truncated subject to {SNS_SUBJECT_MAX_LENGTH} characters")
        
        # Publish to SNS
        logger.info(f"Publishing notification to SNS topic: {SNS_TOPIC_ARN}")
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message,
        )
        
        message_id = response.get("MessageId")
        finding_arn = detail.get("findingArn", "N/A")
        
        logger.info(f"Successfully published message to SNS: {message_id}")
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Notification sent successfully",
                "sns_message_id": message_id,
                "finding_arn": finding_arn
            })
        }
    
    except TimeoutError as e:
        logger.error(f"Lambda timeout error: {e}")
        return {
            "statusCode": 408,
            "body": json.dumps({"error": "Request timeout"})
        }
    
    except ClientError as e:
        logger.exception(f"AWS ClientError publishing to SNS: {e}")
        raise
    
    except RuntimeError as e:
        logger.exception(f"Runtime error: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
    
    except Exception as e:
        logger.exception(f"Unexpected error processing finding: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal server error"})
        }
