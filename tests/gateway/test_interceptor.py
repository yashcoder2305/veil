"""tests/gateway/test_interceptor.py"""

import pytest
from veil.gateway.interceptor import ActionInterceptor, InterceptionError
from veil.gateway.normalizer import NormalizationError


@pytest.fixture
def interceptor():
    return ActionInterceptor()


def _valid_payload(**kwargs):
    payload = {
        "agent_id": "SupportAgent",
        "session_id": "sess-001",
        "tool": "database",
        "operation": "read",
        "resource": "customer_db",
    }
    payload.update(kwargs)
    return payload


def test_intercept_valid_payload_returns_action(interceptor):
    action = interceptor.intercept(_valid_payload())
    assert action.agent_id == "SupportAgent"
    assert action.tool == "database"


def test_intercept_none_raises(interceptor):
    with pytest.raises(InterceptionError, match="null payload"):
        interceptor.intercept(None)


def test_intercept_non_dict_raises(interceptor):
    with pytest.raises(InterceptionError):
        interceptor.intercept([1, 2, 3])


def test_intercept_empty_dict_raises(interceptor):
    with pytest.raises(InterceptionError, match="empty payload"):
        interceptor.intercept({})


def test_intercept_missing_fields_raises_normalization_error(interceptor):
    with pytest.raises(NormalizationError):
        interceptor.intercept({"agent_id": "SupportAgent"})


def test_intercept_string_raises(interceptor):
    with pytest.raises(InterceptionError):
        interceptor.intercept("SELECT * FROM users")
