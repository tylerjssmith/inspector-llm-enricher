"""
Pytest configuration file.
"""
import builtins
import copy
import json
import os
import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError


# --- Set Path ----------------------------------------------------------------
SRC_DIR = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

FIX_DIR = Path(__file__).parent / 'fixtures'
CON_DIR = Path(__file__).parent.parent / 'config'


# --- Lambda Function Setup ---------------------------------------------------
# Required env vars must be set before importing lambda_function
os.environ.setdefault('AWS_REGION', 'us-east-1')
os.environ.setdefault('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:test-topic')

# lambda_function opens config files by name (no path); redirect to config dir
_real_open = builtins.open

def _patched_open(name, *args, **kwargs):
    if name in ('field_schema.json', 'system_prompt.txt'):
        return _real_open(CON_DIR / name, *args, **kwargs)
    return _real_open(name, *args, **kwargs)

with patch('builtins.open', side_effect=_patched_open), \
     patch('boto3.client', return_value=MagicMock()):
    import lambda_function


# --- Fixtures ----------------------------------------------------------------
# Saved
@pytest.fixture
def valid_event():
    return json.loads((FIX_DIR / 'event1.json').read_text())

@pytest.fixture
def field_schema():
    return json.loads((CON_DIR / 'field_schema.json').read_text())

@pytest.fixture
def system_prompt():
    return (CON_DIR / 'system_prompt.txt').read_text()


# Created
@pytest.fixture
def valid_finding(valid_event):
    return valid_event['detail']

@pytest.fixture
def normalized_finding():
    return {
        'severity': 'MEDIUM',
        'type': 'PACKAGE_VULNERABILITY',
        'package': 'snapd',
        'cve': 'CVE-2024-29069',
        'cvss': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L',
        'vendorCreatedAt': 'Thu Jul 25 20:15:00.000 UTC 2024'
    }

@pytest.fixture
def active_event(valid_event):
    event = copy.deepcopy(valid_event)
    event['detail']['status'] = 'ACTIVE'
    return event

@pytest.fixture
def bedrock_response():
    def _make(text: str, stop_reason: str = 'end_turn') -> dict:
        return {
            'stopReason': stop_reason,
            'output': {'message': {'content': [{'text': text}]}}
        }
    return _make

@pytest.fixture
def client_error():
    return ClientError(
        {'Error': {'Code': 'ServiceUnavailableException', 'Message': 'test'}},
        'operation'
    )
