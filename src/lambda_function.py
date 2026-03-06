import boto3
import json
import logging
import os
from botocore.exceptions import ClientError
from typing import Any, Dict, Optional

from helpers import (
    handle_failure,
    normalize_finding,
    make_user_prompt,
    make_email_subj,
    make_email_body
)

# --- Initialize Environment and Global Variables -----------------------------
# Set Logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Get Environment Variables
AWS_REGION = os.environ.get('AWS_REGION')
if AWS_REGION is None:
    raise RuntimeError('AWS_REGION environment variable is not set')
    
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
if SNS_TOPIC_ARN is None:
    raise RuntimeError('SNS_TOPIC_ARN environment variable is not set')

# Load Configuration Files
try:
    with open('field_schema.json', 'r') as file:
        FINDING_SCHEMA = json.load(file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    raise RuntimeError(f'Failed to load field_schema.json: {e}')

try:
    with open('system_prompt.txt', 'r') as file:
        SYSTEM_PROMPT = file.read()
except FileNotFoundError as e:
    raise RuntimeError(f'Failed to load system_prompt.txt: {e}')

# Lambda
SUPPORTED_FINDING_TYPES = ['PACKAGE_VULNERABILITY']

# Bedrock
BEDROCK_MODEL_ID = 'anthropic.claude-3-haiku-20240307-v1:0'
BEDROCK_MAX_TOKENS = 512
bedrock = boto3.client('bedrock-runtime', region_name=AWS_REGION)

# SNS
SNS_SUBJECT_MAX_LENGTH = 100
sns = boto3.client('sns', region_name=AWS_REGION)


# --- Define Helper Functions -------------------------------------------------
def call_bedrock(
    system_prompt: str,
    user_prompt: str,
    model_id: str,
    max_tokens: int = 512
) -> Optional[str]:
    """
    Call LLM via AWS Bedrock Converse API.

    Parameters
    ----------
    system_prompt : str
        System prompt defining assistant role, context, and 
        instructions. Should include host/network description.
    user_prompt : str
        User prompt containing normalized and sanitized 
        Inspector2 finding data returned by normalize_finding().
    model_id : str
        Bedrock model identifier
    max_tokens : int
        Maximum number of tokens in response

    Returns
    -------
    Optional[str]
        Model response text, or None if call fails
    """
    try:
        response = bedrock.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=[
                {
                    "role": "user",
                    "content": [{"text": user_prompt}]
                }
            ],
            inferenceConfig={
                "maxTokens": max_tokens,
                "temperature": 0.0
            }
        )
        stop_reason = response.get('stopReason')
        if stop_reason == 'max_tokens':
            logger.warning(
                'Bedrock response was truncated at max_tokens limit',
                extra={'max_tokens': max_tokens}
            )
        return response["output"]["message"]["content"][0]["text"]
    except ClientError as e:
        logger.error(
            "Bedrock API call failed",
            extra={"error": str(e)}
        )
        return None


def send_email_alert(
    email_subj: str,
    email_body: str,
    topic_arn: str = SNS_TOPIC_ARN
) -> bool:
    """
    Publish notification to SNS topic.

    Parameters
    ----------
    email_subj : str
        Email subject line
    email_body : str
        Email body
    topic_arn : str
        SNS topic ARN

    Returns
    -------
    bool
        True if published successfully, False otherwise
    """
    try:
        sns.publish(
            TopicArn=topic_arn,
            Subject=email_subj,
            Message=email_body
        )
        return True
    except ClientError as e:
        logger.error(
            'SNS publish failed',
            extra={'error': str(e), 'topic_arn': topic_arn}
        )
        return False


# --- Lambda Handler ----------------------------------------------------------
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler to get AI/LLM recommendations for Amazon Inspector findings.
    """
    try:
        # Log Event Received
        logger.info('Received event', extra={
            'source': event.get('source'),
            'detail-type': event.get('detail-type'),
            'account': event.get('account'),
            'region': event.get('region'),
            'resources': event.get('resources')
        })
    
        # Validate Event
        if event.get('source') != 'aws.inspector2':
            logger.info('Skipping event: source is not aws.inspector2')
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Ignored non-Inspector2 finding'
                })
            }
    
        if event.get('detail-type') != 'Inspector2 Finding':
            logger.info('Skipping event: detail-type is not Inspector2 Finding')
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Ignored non-Inspector2 finding'
                })
            }
    
        # Validate Finding
        finding = event.get('detail')
        if not finding:
            logger.error('Finding is missing detail field.')
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Event did not contain finding.'
                })
            }
    
        status = finding.get('status', '').upper()
        if status != 'ACTIVE':
            logger.info('Skipping non-ACTIVE finding', extra={'status': status})
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': f'Skipping {status} finding'
                })
            }
        
        finding_type = finding.get('type', '').upper()
        if finding_type not in SUPPORTED_FINDING_TYPES:
            logger.info('Skipping non-supported type', extra={'type': finding_type})
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': f'Skipping {finding_type} finding'
                })
            }
        
        # Extract Finding ARN for Error Tracking
        finding_arn = finding.get('findingArn', 'unknown')
        
        # (1) Normalize and Sanitize Finding
        normalized = normalize_finding(finding, FINDING_SCHEMA)
        if normalized is None:
            return handle_failure('Normalization', finding_arn, error_code=500)
        
        # (2) Get User Prompt
        user_prompt = make_user_prompt(normalized)

        # (3) Get Recommendation via Bedrock
        response = call_bedrock(
            system_prompt=SYSTEM_PROMPT, 
            user_prompt=user_prompt, 
            model_id=BEDROCK_MODEL_ID, 
            max_tokens=BEDROCK_MAX_TOKENS
        )
        if response is None:
            return handle_failure('Calling Bedrock', finding_arn, error_code=500)
    
        # (4) Send Recommendation via SNS
        email_subj = make_email_subj(normalized, SNS_SUBJECT_MAX_LENGTH)
        email_body = make_email_body(normalized, response)

        if not send_email_alert(email_subj, email_body, SNS_TOPIC_ARN):
            return handle_failure('Sending SNS email', finding_arn, error_code=500)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Notification sent',
            })
        }

    except Exception:
        logger.exception('Unexpected error in lambda_handler')
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error'
            })
        }