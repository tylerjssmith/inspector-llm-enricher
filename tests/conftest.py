"""
Pytest configuration file.
"""
import json
import pytest
import sys
from pathlib import Path


# --- Set Path ----------------------------------------------------------------
SRC_DIR = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

FIX_DIR = Path(__file__).parent / 'fixtures'
CON_DIR = Path(__file__).parent.parent / 'config'


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

