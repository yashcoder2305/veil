"""tests/security/test_policy.py"""

import pytest
from veil.models.action import Action, DataClassification
from veil.models.results import CapabilityResult
from veil.security.policy import PolicyEngine


def make_action(**kwargs) -> Action:
    defaults = dict(
        agent_id="SupportAgent",
        session_id="sess-test",
        tool="database",
        operation="read",
        resource="customer_db",
        data_classification=DataClassification.PII,
        destination="",
        provenance="user_instruction",
    )
    defaults.update(kwargs)
    return Action(**defaults)


def allowed_cap(agent_id="SupportAgent", capability="database.read") -> CapabilityResult:
    return CapabilityResult(
        allowed=True,
        agent_id=agent_id,
        requested_capability=capability,
        reason="Grant matched.",
    )


def denied_cap(agent_id="SupportAgent", capability="database.read") -> CapabilityResult:
    return CapabilityResult(
        allowed=False,
        agent_id=agent_id,
        requested_capability=capability,
        reason="No grant.",
    )


@pytest.fixture
def engine():
    return PolicyEngine()


# --- Clean pass ---

def test_legitimate_read_passes(engine):
    action = make_action()
    result = engine.evaluate(action, allowed_cap())
    assert result.passed is True
    assert result.violated_rules == []


# --- Hard blocks ---

def test_capability_denied_blocks(engine):
    action = make_action()
    result = engine.evaluate(action, denied_cap())
    assert result.passed is False
    assert "POLICY_CAPABILITY_DENIED" in result.violated_rules


def test_shell_tool_blocked(engine):
    action = make_action(tool="shell", operation="execute", resource="/bin/bash")
    result = engine.evaluate(action, allowed_cap(capability="shell.execute"))
    assert result.passed is False
    assert "POLICY_SHELL_FORBIDDEN" in result.violated_rules


def test_pii_to_external_blocked(engine):
    action = make_action(
        data_classification=DataClassification.PII,
        destination="https://evil.com/collect",
    )
    result = engine.evaluate(action, allowed_cap())
    assert result.passed is False
    assert "POLICY_PII_TO_EXTERNAL" in result.violated_rules


def test_financial_to_external_blocked(engine):
    action = make_action(
        tool="http",
        operation="request",
        resource="https://attacker.net",
        data_classification=DataClassification.FINANCIAL,
        destination="https://attacker.net",
    )
    result = engine.evaluate(action, denied_cap(capability="http.request"))
    assert result.passed is False


def test_forbidden_operation_blocked(engine):
    action = make_action(tool="database", operation="execute")
    result = engine.evaluate(action, allowed_cap())
    assert result.passed is False
    assert "POLICY_FORBIDDEN_OPERATION" in result.violated_rules


# --- Soft escalation (not a hard block) ---

def test_write_sensitive_escalates_not_blocks(engine):
    action = make_action(
        operation="write",
        data_classification=DataClassification.PII,
    )
    result = engine.evaluate(action, allowed_cap(capability="database.write"))
    # Soft rule: passed may still be True (if no hard rule fires)
    assert result.requires_escalation is True
    assert "POLICY_WRITE_TO_SENSITIVE_RESOURCE" in result.violated_rules


def test_external_content_provenance_escalates(engine):
    action = make_action(provenance="external_content")
    result = engine.evaluate(action, allowed_cap())
    assert result.requires_escalation is True
    assert "POLICY_SUSPICIOUS_PROVENANCE" in result.violated_rules


# --- Internal destination is safe ---

def test_pii_to_internal_destination_passes(engine):
    action = make_action(
        data_classification=DataClassification.PII,
        destination="localhost",
    )
    result = engine.evaluate(action, allowed_cap())
    assert "POLICY_PII_TO_EXTERNAL" not in result.violated_rules
