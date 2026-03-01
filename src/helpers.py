import json
import logging
import re
import textwrap
from functools import reduce
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

def handle_failure(
    stage: str, 
    finding_arn: str
) -> Dict[str, Any]:
    """
    Handle failures.

    Parameters
    ----------
    stage : str
        Stage where failure occurred
    finding_arn : str
        Finding ARN to log for review

    Returns
    -------
    Dict[str, Any]
        Dictionary containing:
        - 'statusCode': 400
        - 'body': Message indicating where failure occurred
    """
    logger.error(
        'Stage failed', 
        extra={'stage': stage, 'finding_arn': finding_arn}
    )
    return {
        'statusCode': 400,
        'body': json.dumps({'error': f'{stage} failed'})
    }
    

def get_nested(d: Dict, path: tuple) -> Any:
    """
    Traverse nested dictionary using a tuple of keys to
    extract desired value.

    Parameters
    ----------
    d : Dict
        Dictionary to traverse
    path : tuple
        Path of keys to value

    Returns
    -------
    Any
        Desired value or None
    """
    try:
        return reduce(lambda obj, key: obj[key], path, d)
    except (KeyError, IndexError, TypeError):
        return None
    

def normalize_finding(
    finding: Dict[str, Any], 
    schema: Dict[str, Dict]
) -> Optional[Dict[str, str]]:
    """
    Normalize and sanitize Inspector2 finding.

    Parameters
    ----------
    finding : Dict[str, Any]
        Inspector2 finding
    schema : Dict[str, Dict]
        Schema mapping normalized finding names to path and 
        regex pattern

    Returns
    -------
    Optional[Dict[str, str]]
        Normalized and sanitized finding, or None if any field
        is missing, not a string, or fails validation
    """
    normalized = {}
    for field, spec in schema.items():
        value = get_nested(finding, spec['path'])
        if value is None:
            logger.warning(
                'Field missing from finding',
                extra={'field': field, 'path': spec['path']}
            )
            return None
        if not isinstance(value, str):
            logger.warning(
                'Field is not a string',
                extra={'field': field, 'type': type(value).__name__}
            )
            return None
        if not re.fullmatch(spec['pattern'], value):
            logger.warning(
                'Field failed regex validation',
                # Note: 'value' is untrusted input, which is safe for 
                # CloudWatch but should not be forwarded downstream.
                extra={'field': field, 'value': value, 'pattern': spec['pattern']}
            )
            return None
        normalized[field] = value
    return normalized


def make_user_prompt(normalized: Dict[str, str]) -> str:
    """
    Make user prompt from normalized Inspector2 finding.

    Parameters
    ----------
    normalized : Dict[str, str]
        Normalized Inspector2 finding
        Returned by normalize_finding()

    Returns
    -------
    str
        User prompt
    """
    return '\n'.join(f'{k}: {v}' for k, v in normalized.items())


def make_email_subj(
    normalized: Dict[str, str], 
    max_length: int = 50
) -> str:
    """
    Make email subject line.

    Parameters
    ----------
    normalized : Dict[str, str]
        Normalized Inspector2 finding
        Returned by normalize_finding()
    max_length : int, default 50
        Maximum length of subject line

    Returns
    -------
    str
        Email subject line
    """
    severity = normalized.get('severity')
    category = normalized.get('type')

    subj = f'[{severity}] Inspector: {category}'

    if len(subj) > max_length:
        subj = f'{subj[:max(0, max_length - 3)]}...'

    return subj


def make_email_body(
    normalized: Dict[str, str], 
    response: str
) -> str:
    """
    Make email body.

    Parameters
    ----------
    normalized : Dict[str, str]
        Normalized Inspector2 finding
        Returned by normalize_finding()
    response : str
        Remediation recommendation
        Returned by call_bedrock()

    Returns
    -------
    str
        Email body
    """
    lines = [
        '='*70,
        'Amazon Inspector Finding',
        '-'*70,
        'Normalized Inspector Finding',
        json.dumps(normalized, indent=2),
        '',
        '-'*70,
        'AI/LLM Recommendation',
        textwrap.fill(response, width=70)
    ]
    return '\n'.join(lines)