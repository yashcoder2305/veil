"""
veil/security/policy.py

PolicyEngine — hard rule enforcement.

Evaluates an Action against a set of deterministic policy rules AFTER
capability check. Rules here are non-negotiable — they cannot be overridden
by the LLM or the intelligence layer.

Rule naming convention: POLICY_<CATEGORY>_<DESCRIPTION>
Rule evaluation: all rules are checked; all violations are collected.
Result: passed=False if any rule fires. Requires_escalation=True if a rule
        is suspicious but not an outright block (policy defers to risk engine).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from veil.models.action import Action, DataClassification
from veil.models.results import CapabilityResult, PolicyResult


# ---------------------------------------------------------------------------
# Trusted destinations — HTTP requests to these are permitted
# ---------------------------------------------------------------------------

_TRUSTED_DESTINATIONS: frozenset[str] = frozenset({
    "internal-api",
    "internal_api",
    "localhost",
    "127.0.0.1",
    "doomsday-internal",
})

# Any destination containing these substrings is treated as external/untrusted
_EXTERNAL_DESTINATION_SIGNALS: list[str] = [
    "http://", "https://", ".com", ".net", ".org", ".io", ".co",
]

_SENSITIVE_CLASSIFICATIONS: frozenset[DataClassification] = frozenset({
    DataClassification.PII,
    DataClassification.FINANCIAL,
    DataClassification.SECRET,
    DataClassification.CREDENTIAL,
})

_FORBIDDEN_TOOLS: frozenset[str] = frozenset({"shell"})
_FORBIDDEN_OPERATIONS: frozenset[str] = frozenset({"execute", "spawn"})


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    description: str
    check: Callable[[Action, CapabilityResult], bool]
    """Returns True when the rule is VIOLATED."""
    is_hard_block: bool = True
    """
    True  → violation causes PolicyResult.passed=False (hard block).
    False → violation sets requires_escalation=True (soft escalation to risk engine).
    """


def _is_external_destination(destination: str) -> bool:
    if not destination:
        return False
    dest_lower = destination.lower()
    if dest_lower in _TRUSTED_DESTINATIONS:
        return False
    return any(sig in dest_lower for sig in _EXTERNAL_DESTINATION_SIGNALS)


_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="POLICY_CAPABILITY_DENIED",
        description="Action requires a capability the agent does not hold.",
        check=lambda action, cap: not cap.allowed,
        is_hard_block=True,
    ),
    PolicyRule(
        rule_id="POLICY_SHELL_FORBIDDEN",
        description="Shell execution is forbidden for all agents.",
        check=lambda action, cap: action.tool in _FORBIDDEN_TOOLS,
        is_hard_block=True,
    ),
    PolicyRule(
        rule_id="POLICY_FORBIDDEN_OPERATION",
        description="Operation is globally forbidden.",
        check=lambda action, cap: action.operation in _FORBIDDEN_OPERATIONS,
        is_hard_block=True,
    ),
    PolicyRule(
        rule_id="POLICY_PII_TO_EXTERNAL",
        description="PII/sensitive data must not be sent to an external destination.",
        check=lambda action, cap: (
            action.data_classification in _SENSITIVE_CLASSIFICATIONS
            and _is_external_destination(action.destination)
        ),
        is_hard_block=True,
    ),
    PolicyRule(
        rule_id="POLICY_CREDENTIAL_ACCESS_UNREGISTERED",
        description="Credential or secret resource accessed by an unregistered agent.",
        check=lambda action, cap: (
            action.data_classification in {DataClassification.CREDENTIAL, DataClassification.SECRET}
            and not cap.allowed
        ),
        is_hard_block=True,
    ),
    PolicyRule(
        rule_id="POLICY_WRITE_TO_SENSITIVE_RESOURCE",
        description="Write operation to a sensitive resource — escalate for review.",
        check=lambda action, cap: (
            action.operation in {"write", "delete", "overwrite"}
            and action.data_classification in _SENSITIVE_CLASSIFICATIONS
        ),
        is_hard_block=False,  # escalate, don't auto-block
    ),
    PolicyRule(
        rule_id="POLICY_EXTERNAL_HTTP_FROM_NON_RESEARCH",
        description="HTTP request to external destination from an agent not explicitly granted it.",
        check=lambda action, cap: (
            action.tool == "http"
            and _is_external_destination(action.destination or action.resource)
            and not cap.allowed
        ),
        is_hard_block=True,
    ),
    PolicyRule(
        rule_id="POLICY_SUSPICIOUS_PROVENANCE",
        description="Action provenance is external content — heightened scrutiny.",
        check=lambda action, cap: action.provenance == "external_content",
        is_hard_block=False,  # escalate only
    ),
]


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Evaluates an Action against all hard policy rules.

    Usage:
        engine = PolicyEngine()
        result = engine.evaluate(action, capability_result)
        if not result.passed:
            # hard block
    """

    def evaluate(
        self,
        action: Action,
        capability_result: CapabilityResult,
    ) -> PolicyResult:
        """
        Run all policy rules against the action.

        Returns PolicyResult with:
          - passed=False  if any hard rule fires
          - requires_escalation=True if any soft rule fires
          - violated_rules listing all fired rule IDs
        """
        violated: list[str] = []
        has_hard_violation = False
        requires_escalation = False

        for rule in _RULES:
            try:
                if rule.check(action, capability_result):
                    violated.append(rule.rule_id)
                    if rule.is_hard_block:
                        has_hard_violation = True
                    else:
                        requires_escalation = True
            except Exception:
                # A rule check must never crash the pipeline — fail closed
                violated.append(rule.rule_id)
                has_hard_violation = True

        if not violated:
            return PolicyResult(
                passed=True,
                violated_rules=[],
                reason="All policy rules passed.",
                requires_escalation=False,
            )

        reasons = [r for r in violated]
        reason_text = (
            f"Hard policy violation(s): {', '.join(reasons)}"
            if has_hard_violation
            else f"Policy escalation triggered: {', '.join(reasons)}"
        )

        return PolicyResult(
            passed=not has_hard_violation,
            violated_rules=violated,
            reason=reason_text,
            requires_escalation=requires_escalation,
        )
