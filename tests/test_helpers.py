import json

from helpers import (
    handle_failure,
    get_nested,
    normalize_finding,
    make_user_prompt,
    make_email_subj,
    make_email_body
)


# --- handle_failure() --------------------------------------------------------
def test_handle_failure(valid_finding):
    finding_arn = valid_finding.get('findingArn')
    error = handle_failure(stage='Test', finding_arn=finding_arn, error_code=500)
    assert error['statusCode'] == 500
    body = json.loads(error['body'])
    assert isinstance(body['error'], str)
    assert body['error'] == 'Test failed'


def test_handle_failure_error_code(valid_finding):
    finding_arn = valid_finding.get('findingArn')
    error = handle_failure(stage='Test', finding_arn=finding_arn, error_code=400)
    assert error['statusCode'] == 400


# --- get_nested() ------------------------------------------------------------
def test_get_nested(valid_finding, field_schema):
    spec = field_schema['cvss']
    value = get_nested(valid_finding, spec['path'])
    assert isinstance(value, str)
    assert value == 'CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L'


def test_get_nested_missing_path(valid_finding):
    value = get_nested(valid_finding, ['nonexistent', 'path'])
    assert value is None


def test_get_nested_non_subscriptable(valid_finding):
    value = get_nested(valid_finding, ['severity', 'nested'])
    assert value is None


# --- normalize_finding() -----------------------------------------------------
def test_normalize_finding(valid_finding, field_schema):
    finding = normalize_finding(valid_finding, field_schema)
    assert isinstance(finding, dict)
    for key in field_schema.keys():
        assert key in finding
        assert isinstance(finding[key], str)


def test_normalize_finding_field_missing(valid_finding, field_schema):
    del valid_finding['severity']
    finding = normalize_finding(valid_finding, field_schema)
    assert finding is None


def test_normalize_finding_field_not_string(valid_finding, field_schema):
    valid_finding['severity'] = 99
    finding = normalize_finding(valid_finding, field_schema)
    assert finding is None


def test_normalize_finding_field_invalid(valid_finding, field_schema):
    valid_finding['severity'] = 'INVALID'
    finding = normalize_finding(valid_finding, field_schema)
    assert finding is None


# --- make_user_prompt() ------------------------------------------------------
def test_make_user_prompt(normalized_finding):
    prompt = make_user_prompt(normalized_finding)
    assert isinstance(prompt, str)
    for key, value in normalized_finding.items():
        assert key in prompt
        assert value in prompt


# --- make_email_subj() -------------------------------------------------------
def test_make_email_subj(normalized_finding):
    email_subj = make_email_subj(normalized_finding)
    assert isinstance(email_subj, str)
    assert '[MEDIUM]' in email_subj
    assert 'PACKAGE_VULNERABILITY' in email_subj
    assert 'Inspector' in email_subj


def test_make_email_subj_max_length(normalized_finding):
    long_finding = {**normalized_finding, 'type': normalized_finding['type'] * 2}
    email_subj = make_email_subj(long_finding, max_length=50)
    assert isinstance(email_subj, str)
    assert len(email_subj) <= 50
    assert email_subj.endswith('...')


# --- make_email_body() -------------------------------------------------------
def test_make_email_body(normalized_finding):
    response = 'Update packages.'
    email_body = make_email_body(normalized_finding, response)
    assert isinstance(email_body, str)
    assert 'Amazon Inspector Finding' in email_body
    assert 'Normalized Inspector Finding' in email_body
    for key in normalized_finding:
        assert key in email_body
    assert 'AI/LLM Recommendation' in email_body
    assert response in email_body


# --- system_prompt -----------------------------------------------------------
def test_system_prompt_untrusted_input_instruction(system_prompt):
    assert 'untrusted' in system_prompt.lower()