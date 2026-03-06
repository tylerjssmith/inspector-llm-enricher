import json
from unittest.mock import patch

import lambda_function


# --- call_bedrock() ----------------------------------------------------------
def test_call_bedrock_success(bedrock_response):
    expected = 'Update the snapd package.'
    with patch.object(lambda_function.bedrock, 'converse',
                      return_value=bedrock_response(expected)):
        result = lambda_function.call_bedrock(
            system_prompt='system',
            user_prompt='user',
            model_id=lambda_function.BEDROCK_MODEL_ID
        )
    assert result == expected


def test_call_bedrock_client_error(client_error):
    with patch.object(lambda_function.bedrock, 'converse',
                      side_effect=client_error):
        result = lambda_function.call_bedrock(
            system_prompt='system',
            user_prompt='user',
            model_id=lambda_function.BEDROCK_MODEL_ID
        )
    assert result is None


def test_call_bedrock_max_tokens(bedrock_response):
    expected = 'Truncated response'
    with patch.object(lambda_function.bedrock, 'converse',
                      return_value=bedrock_response(expected, stop_reason='max_tokens')):
        result = lambda_function.call_bedrock(
            system_prompt='system',
            user_prompt='user',
            model_id=lambda_function.BEDROCK_MODEL_ID
        )
    assert result == expected


# --- send_email_alert() ------------------------------------------------------
def test_send_email_alert_success():
    with patch.object(lambda_function.sns, 'publish'):
        result = lambda_function.send_email_alert(
            email_subj='[MEDIUM] Inspector: PACKAGE_VULNERABILITY',
            email_body='body',
            topic_arn=lambda_function.SNS_TOPIC_ARN
        )
    assert result is True


def test_send_email_alert_client_error(client_error):
    with patch.object(lambda_function.sns, 'publish',
                      side_effect=client_error):
        result = lambda_function.send_email_alert(
            email_subj='[MEDIUM] Inspector: PACKAGE_VULNERABILITY',
            email_body='body',
            topic_arn=lambda_function.SNS_TOPIC_ARN
        )
    assert result is False


# --- lambda_handler() --------------------------------------------------------
def test_lambda_handler_success(active_event, bedrock_response):
    with patch.object(lambda_function.bedrock, 'converse',
                      return_value=bedrock_response('Update the snapd package.')), \
         patch.object(lambda_function.sns, 'publish'):
        result = lambda_function.lambda_handler(active_event, None)
    assert result['statusCode'] == 200
    assert json.loads(result['body'])['message'] == 'Notification sent'


def test_lambda_handler_non_active_status(valid_event):
    result = lambda_function.lambda_handler(valid_event, None)
    assert result['statusCode'] == 200
    assert 'CLOSED' in json.loads(result['body'])['message']


def test_lambda_handler_unsupported_type(active_event):
    active_event['detail']['type'] = 'NETWORK_REACHABILITY'
    result = lambda_function.lambda_handler(active_event, None)
    assert result['statusCode'] == 200
    assert 'NETWORK_REACHABILITY' in json.loads(result['body'])['message']


def test_lambda_handler_normalization_failure(active_event):
    active_event['detail']['severity'] = 'INVALID'
    result = lambda_function.lambda_handler(active_event, None)
    assert result['statusCode'] == 500


def test_lambda_handler_non_inspector_source(active_event):
    active_event['source'] = 'aws.ec2'
    result = lambda_function.lambda_handler(active_event, None)
    assert result['statusCode'] == 200
