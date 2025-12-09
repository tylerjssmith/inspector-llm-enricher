# lambda/sns_handler/build_email.py
import json

from typing import Dict, Any
from call_llm import call_llm_for_finding

def build_email_subject(detail: Dict[str, Any]) -> str:
    severity     = detail.get("severity", "UNKNOWN")
    finding_type = detail.get("type", "UNKNOWN_TYPE")
    title        = detail.get("title", "Inspector Finding")
    short_title  = (title[:80] + "…") if len(title) > 80 else title

    return f"[Inspector] {severity} - {finding_type} - {short_title}"

def build_email_body(event: Dict[str, Any], llm_result: Dict[str, str]) -> str:
    account_id   = event.get("account", "UNKNOWN")
    region       = event.get("region", "UNKNOWN")
    detail       = event.get("detail", {}) or {}

    severity     = detail.get("severity", "UNKNOWN")
    status       = detail.get("status", "UNKNOWN")
    title        = detail.get("title", "N/A")
    description  = detail.get("description", "N/A")
    finding_arn  = detail.get("findingArn", "N/A")
    finding_type = detail.get("type", "N/A")

    llm_response = llm_result.get("response") or "No LLM explanation available."

    lines = [
        "New Amazon Inspector Finding",
        "==================================================",
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
        "",
        "LLM Explanation and Recommendation",
        "--------------------------------------------------",
        llm_response,
        "",
        "Raw Inspector Finding:",
        "--------------------------------------------------",
        json.dumps(event, indent=2, default=str),
    ]

    return "\n".join(lines)