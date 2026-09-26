"""
veil/gateway/executor.py

ActionExecutor — enforces the "no execution without ALLOW" rule.

This is the final gate. If the decision is anything other than ALLOW,
the action never reaches a real tool. This module does not contain
security logic — it only enforces the decision the pipeline produced.

Real tool dispatch:
  In production the executor would forward the action to the actual tool
  implementation. In the simulator it delegates to the tool stubs. For the
  hackathon the stubs are the implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from veil.models.action import Action
from veil.models.decisions import Decision, DecisionResult


@dataclass
class ExecutionResult:
    """Result of an execution attempt."""

    executed: bool
    """True only when the action was actually dispatched to the tool."""

    action_id: str
    """ID of the Action that was evaluated."""

    decision: Decision
    """The decision that determined this outcome."""

    tool_output: Optional[Any] = None
    """Output from the tool, if execution occurred."""

    block_reason: Optional[str] = None
    """Reason for non-execution, if the action was not executed."""


class ExecutionBlockedError(RuntimeError):
    """Raised when the caller tries to execute a blocked action."""
    pass


class ActionExecutor:
    """
    Executes an Action if and only if the decision is ALLOW.

    Usage:
        executor = ActionExecutor(tool_registry=my_tools)
        result = executor.execute(action, decision_result)
    """

    def __init__(self, tool_registry: Optional[Any] = None) -> None:
        """
        Args:
            tool_registry: Optional mapping of tool name → callable stub.
                           If None, a placeholder response is returned for ALLOW.
        """
        self._tool_registry = tool_registry or {}

    def execute(self, action: Action, decision_result: DecisionResult) -> ExecutionResult:
        """
        Gate the action on the decision.

        Only Decision.ALLOW proceeds to tool dispatch.
        All other decisions return a blocked ExecutionResult — no exception,
        no side effects.

        Args:
            action:          The normalized Action.
            decision_result: Output of the VEIL decision engine.

        Returns:
            ExecutionResult indicating whether execution occurred.
        """
        if decision_result.decision != Decision.ALLOW:
            return ExecutionResult(
                executed=False,
                action_id=action.action_id,
                decision=decision_result.decision,
                tool_output=None,
                block_reason=decision_result.reason,
            )

        # Dispatch to tool stub / real tool
        tool_output = self._dispatch(action)

        return ExecutionResult(
            executed=True,
            action_id=action.action_id,
            decision=Decision.ALLOW,
            tool_output=tool_output,
            block_reason=None,
        )

    def _dispatch(self, action: Action) -> Any:
        """
        Forward the action to a registered tool handler.
        Falls back to a generic acknowledgement if no handler is registered.
        """
        handler = self._tool_registry.get(action.tool)
        if handler is not None:
            return handler(action)
        # Placeholder — replaced by simulator tool stubs
        return {
            "status": "ok",
            "tool": action.tool,
            "operation": action.operation,
            "resource": action.resource,
            "note": "no tool handler registered; returning stub response",
        }
