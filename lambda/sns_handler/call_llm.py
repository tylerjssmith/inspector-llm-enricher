# lambda/sns_handler/call_llm.py
import logging
import json
import os
import boto3

from typing import Any, Dict
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

BEDROCK_REGION   = os.environ.get("AWS_REGION", "us-west-2")
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "amazon.titan-text-express-v1")

bedrock_client = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)

def normalize_finding_for_llm(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize Inspector2 finding by extracting relevant fields and 
    building compact, LLM-friendly payload.
    """
    
    detail = event.get("detail", {}) or {}
    resources = detail.get("resources") or []
    primary_resource = resources[0] if resources else {}
    pvd = detail.get("packageVulnerabilityDetails", {}) or {}

    return {
        "finding_arn": detail.get("findingArn"),
        "severity": detail.get("severity"),
        "status": detail.get("status"),
        "title": detail.get("title"),
        "description": detail.get("description"),
        "inspector_score": detail.get("inspectorScore"),
        "resource": {
            "type": primary_resource.get("type"),
            "id": primary_resource.get("id"),
            "region": primary_resource.get("region"),
        },
        "package_vulnerability": {
            "vulnerability_id": pvd.get("vulnerabilityId"),
            "source_severity": pvd.get("sourceSeverity"),
            "reference_urls": pvd.get("referenceUrls") or [],
        },
        "timestamps": {
            "first_observed_at": detail.get("firstObservedAt"),
            "last_observed_at": detail.get("lastObservedAt"),
            "updated_at": detail.get("updatedAt"),
        },
    }

def build_prompt_from_finding(finding: Dict[str, Any]) -> str:
    """
    Build LLM prompt using Inspector2 finding.
    """
    
    return (
        "You are an experienced cloud security engineer.\n\n"
        "You are given a JSON representation of an Amazon Inspector finding for an EC2 instance.\n"
        "1. Explain the vulnerability in clear, concise language suitable for a security engineer.\n"
        "2. Provide concrete, actionable remediation steps, including relevant Linux commands or AWS actions.\n"
        "3. If appropriate, mention whether a reboot is required and any operational caveats.\n"
        "4. Keep the answer under 600 words.\n\n"
        "Finding JSON:\n"
        f"{json.dumps(finding, indent=2)}"
    )


def call_llm_for_finding(event: Dict[str, Any]) -> Dict[str, str]:
    """
    Normalize Inspector2 finding, build LLM prompt, call LLM, and
    return explanation and remediation recommendation.
    """
    
    # Prepare LLM Request
    finding = normalize_finding_for_llm(event)
    request = build_prompt_from_finding(finding)
    
    request = {
        "inputText": request,
        "textGenerationConfig": {
            "temperature": 0.6,
            "topP": 0.6,
            "maxTokenCount": 1028
        }
    }

    request = json.dumps(request)

    # Call LLM
    try:
        response = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=request,
            contentType="application/json",
            accept="application/json"
        )

    except (BotoCoreError, ClientError) as exc:
        logger.exception("Error calling LLM model: %s", exc)
        return {
            "response": "LLM call failed."
        }

    # Process and Return LLM Response
    raw     = response["body"].read().decode("utf-8")
    data    = json.loads(raw)  
    outputs = data["results"][0]["outputText"] or []
    outputs = outputs.strip() 

    if not outputs:
        return {
            "response": "LLM call returned empty text."
        }

    return {
        "response": outputs
    }
