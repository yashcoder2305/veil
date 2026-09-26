"""tests/gateway/test_normalizer.py"""

import pytest
from veil.gateway.normalizer import ActionNormalizer, NormalizationError
from veil.models.action import DataClassification


@pytest.fixture
def normalizer():
    return ActionNormalizer()


def _base_payload(**kwargs):
    payload = {
        "agent_id": "SupportAgent",
        "session_id": "sess-001",
        "tool": "database",
        "operation": "read",
        "resource": "customer_db",
    }
    payload.update(kwargs)
    return payload


def test_normalize_minimal_payload(normalizer):
    action = normalizer.normalize(_base_payload())
    assert action.agent_id == "SupportAgent"
    assert action.session_id == "sess-001"
    assert action.tool == "database"
    assert action.operation == "read"
    assert action.resource == "customer_db"


def test_normalize_sets_data_classification(normalizer):
    action = normalizer.normalize(_base_payload(resource="customer_db"))
    assert action.data_classification == DataClassification.PII


def test_normalize_payment_records_classification(normalizer):
    action = normalizer.normalize(_base_payload(resource="payment_records"))
    assert action.data_classification == DataClassification.FINANCIAL


def test_normalize_derives_capability(normalizer):
    action = normalizer.normalize(_base_payload())
    assert action.requested_capability == "database.read"


def test_normalize_explicit_capability_preserved(normalizer):
    action = normalizer.normalize(_base_payload(requested_capability="database.read.pii"))
    assert action.requested_capability == "database.read.pii"


def test_normalize_camelcase_aliases(normalizer):
    raw = {
        "agentId": "ResearchAgent",
        "sessionId": "sess-002",
        "tool": "http",
        "operation": "request",
        "resource": "https://example.com",
    }
    action = normalizer.normalize(raw)
    assert action.agent_id == "ResearchAgent"
    assert action.session_id == "sess-002"


def test_normalize_alias_url_maps_to_resource(normalizer):
    raw = {
        "agent_id": "ResearchAgent",
        "session_id": "sess-003",
        "tool": "http",
        "operation": "request",
        "url": "https://example.com",
    }
    action = normalizer.normalize(raw)
    assert action.resource == "https://example.com"


def test_normalize_missing_required_field_raises(normalizer):
    raw = {
        "agent_id": "SupportAgent",
        "session_id": "sess-001",
        "tool": "database",
        # missing operation and resource
    }
    with pytest.raises(NormalizationError, match="missing required fields"):
        normalizer.normalize(raw)


def test_normalize_non_dict_raises(normalizer):
    with pytest.raises(NormalizationError):
        normalizer.normalize("not a dict")  # type: ignore


def test_normalize_extra_keys_stripped(normalizer):
    raw = _base_payload(unknown_field="should_be_ignored")
    action = normalizer.normalize(raw)
    assert not hasattr(action, "unknown_field")


def test_normalize_metadata_passed_through(normalizer):
    raw = _base_payload(metadata={"user_input": "hello"})
    action = normalizer.normalize(raw)
    assert action.metadata == {"user_input": "hello"}
