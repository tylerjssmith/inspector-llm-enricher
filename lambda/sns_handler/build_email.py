"""
Functions to build emails with Amazon Inspector findings, including
LLM-enriched remediation recommendations.
"""

import json
from typing import Any, Dict


def build_email_subject(detail: Dict[str, Any]) -> str:
    """
    Builds subject line for email with Amazon Inspector finding,
    including LLM-enriched remediation recommendation.
    
    Args:
        detail: The 'detail' field from Inspector2 EventBridge event
        
    Returns:
        Formatted email subject string (suitable for SNS subject line)
    """
    severity = detail.get("severity", "UNKNOWN")
    finding_type = detail.get("type", "UNKNOWN_TYPE")
    title = detail.get("title", "Inspector Finding")
    
    # Sanitize title for email subject (remove newlines and extra whitespace)
    title = " ".join(title.split())
    
    # Truncate title if too long, leaving room for prefix
    short_title = (title[:77] + "...") if len(title) > 80 else title
    
    return f"[Inspector] {severity} - {finding_type} - {short_title}"


def build_email_body(event: Dict[str, Any], llm_result: Dict[str, str]) -> str:
    """
    Builds email body with Amazon Inspector finding, including 
    LLM-enriched remediation recommendation.
    
    Args:
        event: Complete EventBridge event from Inspector2
        llm_result: Dictionary containing LLM response
        
    Returns:
        Formatted email body string with finding details and recommendations
    """
    account_id = event.get("account", "UNKNOWN")
    region = event.get("region", "UNKNOWN")
    detail = event.get("detail", {})
    
    if not detail:
        detail = {}
    
    severity = detail.get("severity", "UNKNOWN")
    status = detail.get("status", "UNKNOWN")
    title = detail.get("title", "N/A")
    description = detail.get("description", "N/A")
    finding_arn = detail.get("findingArn", "N/A")
    finding_type = detail.get("type", "N/A")
    
    # Extract remediation URL if available
    remediation = detail.get("remediation", {})
    recommendation = remediation.get("recommendation", {}) if remediation else {}
    recommendation_url = recommendation.get("Url", "N/A") if recommendation else "N/A"
    
    # Handle LLM response with graceful fallback
    llm_response = llm_result.get("response", "").strip()
    if not llm_response:
        llm_response = "No remediation recommendations available at this time."
    
    lines = [
        "New Amazon Inspector Finding",
        "=" * 60,
        "",
        f"Account: {account_id}",
        f"Region: {region}",
        "",
        f"Severity: {severity}",
        f"Status: {status}",
        "",
        f"Title: {title}",
        f"Description: {description}",
        "",
        f"Finding ARN: {finding_arn}",
        f"Finding Type: {finding_type}",
    ]
    
    # Add AWS recommendation URL if available
    if recommendation_url != "N/A":
        lines.extend(["", f"AWS Recommendation: {recommendation_url}"])
    
    lines.extend([
        "",
        "AI-Generated Remediation Guidance:",
        "-" * 60,
        llm_response,
        "",
        "⚠️  Note: AI recommendations should be validated before implementation.",
        "",
        "Raw Inspector Finding:",
        "-" * 60,
        json.dumps(event, indent=2, default=str),
    ])
    
    return "\n".join(lines)
