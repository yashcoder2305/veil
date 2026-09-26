"""tests/gateway/test_executor.py"""

import pytest
from veil.gateway.executor import ActionExecutor, ExecutionResult
from veil.models.action import Action
from veil.models.decisions import Decision, DecisionResult


def make_action(**kwargs) -> Action:
    defaults = dict(
        agent_id="SupportAgent",
        session_id="sess-001",
        tool="database",
        operation="read",
        resource="customer_db",
    )
    defaults.update(kwargs)
    return Action(**defaults)


def make_decision(decision: Decision, reason: str = "test") -> DecisionResult:
    return DecisionResult(decision=decision, reason=reason, triggered_rules=[])


@pytest.fixture
def executor():
    return ActionExecutor()


# --- ALLOW ---

def test_allow_executes(executor):
    action = make_action()
    result = executor.execute(action, make_decision(Decision.ALLOW))
    assert result.executed is True
    assert result.decision == Decision.ALLOW
    assert result.block_reason is None


def test_allow_returns_tool_output(executor):
    action = make_action()
    result = executor.execute(action, make_decision(Decision.ALLOW))
    assert result.tool_output is not None


# --- BLOCK ---

def test_block_does_not_execute(executor):
    action = make_action()
    result = executor.execute(action, make_decision(Decision.BLOCK, "capability denied"))
    assert result.executed is False
    assert result.decision == Decision.BLOCK
    assert result.block_reason == "capability denied"
    assert result.tool_output is None


# --- WARN ---

def test_warn_does_not_execute(executor):
    action = make_action()
    result = executor.execute(action, make_decision(Decision.WARN))
    assert result.executed is False
    assert result.decision == Decision.WARN


# --- REQUIRE_APPROVAL ---

def test_require_approval_does_not_execute(executor):
    action = make_action()
    result = executor.execute(action, make_decision(Decision.REQUIRE_APPROVAL))
    assert result.executed is False


# --- REVOKE ---

def test_revoke_does_not_execute(executor):
    action = make_action()
    result = executor.execute(action, make_decision(Decision.REVOKE))
    assert result.executed is False
    assert result.decision == Decision.REVOKE


# --- Custom tool handler ---

def test_custom_tool_handler_called_on_allow():
    called_with = []

    def my_handler(action):
        called_with.append(action.tool)
        return {"rows": []}

    executor = ActionExecutor(tool_registry={"database": my_handler})
    action = make_action()
    result = executor.execute(action, make_decision(Decision.ALLOW))
    assert result.executed is True
    assert called_with == ["database"]
    assert result.tool_output == {"rows": []}


def test_custom_tool_handler_not_called_on_block():
    called = []

    def my_handler(action):
        called.append(True)
        return {}

    executor = ActionExecutor(tool_registry={"database": my_handler})
    action = make_action()
    executor.execute(action, make_decision(Decision.BLOCK))
    assert called == []
