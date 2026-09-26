"""tests/security/test_capabilities.py"""

import pytest
from veil.models.action import Action, DataClassification
from veil.security.capabilities import CapabilityManager


def make_action(**kwargs) -> Action:
    defaults = dict(
        agent_id="SupportAgent",
        session_id="sess-test",
        tool="database",
        operation="read",
        resource="customer_db",
    )
    defaults.update(kwargs)
    return Action(**defaults)


@pytest.fixture
def manager():
    return CapabilityManager()


# --- SupportAgent ---

def test_support_agent_read_customer_db_allowed(manager):
    action = make_action(agent_id="SupportAgent", tool="database", operation="read", resource="customer_db")
    result = manager.check(action)
    assert result.allowed is True


def test_support_agent_write_customer_db_denied(manager):
    action = make_action(agent_id="SupportAgent", tool="database", operation="write", resource="customer_db")
    result = manager.check(action)
    assert result.allowed is False


def test_support_agent_read_payment_records_denied(manager):
    action = make_action(agent_id="SupportAgent", tool="database", operation="read", resource="payment_records")
    result = manager.check(action)
    assert result.allowed is False


def test_support_agent_http_request_denied(manager):
    action = make_action(agent_id="SupportAgent", tool="http", operation="request", resource="https://evil.com")
    result = manager.check(action)
    assert result.allowed is False


# --- ResearchAgent ---

def test_research_agent_http_allowed(manager):
    action = make_action(agent_id="ResearchAgent", tool="http", operation="request", resource="https://example.com")
    result = manager.check(action)
    assert result.allowed is True


def test_research_agent_write_file_denied(manager):
    action = make_action(agent_id="ResearchAgent", tool="file", operation="write", resource="internal_docs")
    result = manager.check(action)
    assert result.allowed is False


# --- FinanceAgent ---

def test_finance_agent_write_payment_records_allowed(manager):
    action = make_action(agent_id="FinanceAgent", tool="database", operation="write", resource="payment_records")
    result = manager.check(action)
    assert result.allowed is True


def test_finance_agent_read_customer_db_denied(manager):
    action = make_action(agent_id="FinanceAgent", tool="database", operation="read", resource="customer_db")
    result = manager.check(action)
    assert result.allowed is False


# --- Unknown agent ---

def test_unknown_agent_denied(manager):
    action = make_action(agent_id="UnknownBot", tool="database", operation="read", resource="customer_db")
    result = manager.check(action)
    assert result.allowed is False
    assert "not registered" in result.reason


# --- Globally forbidden ---

def test_shell_execute_globally_forbidden(manager):
    action = make_action(agent_id="SupportAgent", tool="shell", operation="execute", resource="/bin/bash")
    result = manager.check(action)
    assert result.allowed is False
    assert "globally forbidden" in result.reason


# --- Revocation stub ---

class _MockRevocationStore:
    def is_revoked(self, agent_id, session_id, capability):
        return capability == "database.read"


def test_revoked_capability_denied():
    manager = CapabilityManager(revocation_store=_MockRevocationStore())
    action = make_action(agent_id="SupportAgent", tool="database", operation="read", resource="customer_db")
    result = manager.check(action)
    assert result.allowed is False
    assert result.is_revoked is True
