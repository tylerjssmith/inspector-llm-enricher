"""
Functions to call LLM to obtain remediation recommendations for
Amazon Inspector findings.
"""

import logging
import json
import os
from typing import Any, Dict

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

BEDROCK_REGION = os.environ.get("AWS_REGION", "us-west-2")
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "amazon.titan-text-express-v1")

config = Config(
    retries={'max_attempts': 3, 'mode': 'adaptive'}
)
bedrock_client = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION, config=config)

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNTRIAGED"}


def normalize_finding_for_llm(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize Inspector2 finding by extracting relevant fields and 
    building compact, LLM-friendly payload.
    
    Args:
        event: EventBridge event containing Inspector2 finding
        
    Returns:
        Normalized finding dictionary
        
    Raises:
        ValueError: If event structure is invalid or missing required fields
    """
    try:
        detail = event.get("detail")
        if not detail:
            raise ValueError("Missing 'detail' field in event")
        
        resources = detail.get("resources", [])
        primary_resource = resources[0] if resources else {}
        pvd = detail.get("packageVulnerabilityDetails", {})
        
        severity = detail.get("severity", "UNKNOWN")
        if severity not in VALID_SEVERITIES and severity != "UNKNOWN":
            logger.warning(f"Unexpected severity value: {severity}")
        
        title = detail.get("title", "Unknown")
        description = detail.get("description", "N/A")
        
        # Limit field lengths to prevent excessive token usage
        if len(title) > 200:
            title = title[:200]
            logger.info("Truncated title to 200 characters")
        
        if len(description) > 1000:
            description = description[:1000]
            logger.info("Truncated description to 1000 characters")
        
        # Extract EC2 instance details including OS information
        resource_details = primary_resource.get("details", {})
        aws_ec2_instance = resource_details.get("awsEc2Instance", {})
        
        # Get platform/OS information
        platform = aws_ec2_instance.get("platform")
        image_id = aws_ec2_instance.get("imageId")

        return {
            "vulnerability_id": pvd.get("vulnerabilityId", "N/A"),
            "title": title,
            "description": description,
            "severity": severity,
            "inspector_score": detail.get("inspectorScore"),
            "resource_type": primary_resource.get("type", "Unknown"),
            "platform": platform if platform else "Unknown",
            "image_id": image_id if image_id else "N/A",
            "first_observed_at": detail.get("firstObservedAt"),
            "last_observed_at": detail.get("lastObservedAt"),
            "updated_at": detail.get("updatedAt")
        }
    except (KeyError, IndexError, TypeError) as e:
        logger.error(f"Error normalizing finding: {e}")
        raise ValueError(f"Invalid finding structure: {e}")


def build_prompt_from_finding(finding: Dict[str, Any]) -> str:
    """
    Build LLM prompt using Inspector2 finding.
    
    Args:
        finding: Normalized finding dictionary
        
    Returns:
        Formatted prompt string for LLM
    """
    platform = finding.get("platform", "Unknown")
    platform_info = f" The EC2 instance is running {platform}." if platform != "Unknown" else ""
    
    return (
        "You are an experienced cloud security engineer.\n\n"
        f"{platform_info}\n"
        "You are given a JSON representation of an Amazon Inspector finding on an EC2 instance.\n"
        "1. Explain the vulnerability in clear, concise language.\n"
        "2. Provide specific remediation steps, including relevant Linux commands.\n"
        "3. Keep the answer under 600 words.\n\n"
        "Finding JSON:\n"
        f"{json.dumps(finding, indent=2)}"
    )


def call_llm_for_finding(event: Dict[str, Any]) -> Dict[str, str]:
    """
    Normalize Inspector2 finding, build LLM prompt, call LLM, and
    return remediation recommendation.
    
    Args:
        event: EventBridge event containing Inspector2 finding
        
    Returns:
        Dictionary containing LLM response or error message
    """
    try:
        finding = normalize_finding_for_llm(event)
        prompt = build_prompt_from_finding(finding)
        
        request_body = {
            "inputText": prompt,
            "textGenerationConfig": {
                "temperature": 0.3,
                "topP": 0.9,
                "maxTokenCount": 2048
            }
        }
        
        logger.info(f"Calling Bedrock model: {BEDROCK_MODEL_ID}")
        
        response = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(request_body),
            contentType="application/json",
            accept="application/json"
        )
        
        raw = response["body"].read().decode("utf-8")
        data = json.loads(raw)
        
        results = data.get("results", [])
        if not results:
            logger.warning("LLM response contained no results")
            return {"response": "LLM generated no recommendations."}
        
        output_text = results[0].get("outputText", "")
        
        if not output_text or not output_text.strip():
            logger.warning("LLM returned empty output text")
            return {"response": "LLM generated no recommendations."}
        
        logger.info("Successfully received LLM response")
        return {"response": output_text.strip()}
        
    except ValueError as e:
        logger.error(f"Invalid finding data: {e}")
        return {"response": f"Unable to process finding: {str(e)}"}
    
    except (BotoCoreError, ClientError) as e:
        logger.exception(f"AWS API error calling LLM: {e}")
        return {"response": "LLM service temporarily unavailable."}
    
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        logger.exception(f"Error parsing LLM response: {e}")
        return {"response": "Error processing LLM response."}
    
    except Exception as e:
        logger.exception(f"Unexpected error in LLM call: {e}")
        return {"response": "An unexpected error occurred generating recommendations."}
