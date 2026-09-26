"""
veil/models/results.py

Intermediate result types produced by each security layer in the VEIL pipeline.

These are the data contracts between Durga's deterministic layer and Yash's
intelligence layer. Keep them stable — changing a field name here breaks both
sides.

Layer ownership:
  CapabilityResult  → veil/security/capabilities.py  (Durga)
  PolicyResult      → veil/security/policy.py         (Durga)
  RiskResult        → veil/security/risk.py            (Yash)
  InjectionResult   → veil/security/injection.py       (Yash)
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Risk level enum — shared across RiskEngine and DecisionEngine
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    """Ordered risk severity. CRITICAL always triggers agentic analysis."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# CapabilityResult
# ---------------------------------------------------------------------------


class CapabilityResult(BaseModel):
    """
    Output of CapabilityManager.check(action).

    Produced by: veil/security/capabilities.py (Durga)
    Consumed by: PolicyEngine, RiskEngine, DecisionEngine
    """

    allowed: bool = Field(
        description="True if the agent holds the requested capability.",
    )
    agent_id: str = Field(
        description="Agent whose capabilities were checked.",
    )
    requested_capability: str = Field(
        description="Capability token that was evaluated, e.g. 'database.read'.",
    )
    reason: str = Field(
        description="Explanation: which rule granted or denied the capability.",
    )
    is_revoked: bool = Field(
        default=False,
        description="True if the capability was previously revoked by RevocationEngine "
                    "for this session. Distinct from never having been granted.",
    )

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# PolicyResult
# ---------------------------------------------------------------------------


class PolicyResult(BaseModel):
    """
    Output of PolicyEngine.evaluate(action, capability_result).

    Produced by: veil/security/policy.py (Durga)
    Consumed by: RiskEngine, DecisionEngine
    """

    passed: bool = Field(
        description="True if no hard policy rule was violated.",
    )
    violated_rules: list[str] = Field(
        default_factory=list,
        description="Identifiers of all rules that fired, e.g. "
                    "['POLICY_PII_TO_EXTERNAL', 'POLICY_SHELL_FORBIDDEN'].",
    )
    reason: str = Field(
        description="Summary explanation of the policy evaluation outcome.",
    )
    requires_escalation: bool = Field(
        default=False,
        description="True when the policy violation is not an outright block but "
                    "warrants escalation to the intelligence layer.",
    )

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# RiskResult
# ---------------------------------------------------------------------------


class RiskResult(BaseModel):
    """
    Output of RiskEngine.score(action, capability_result, policy_result, trajectory_analysis).

    Produced by: veil/security/risk.py (Yash)
    Consumed by: DecisionEngine
    """

    level: RiskLevel = Field(
        description="Overall risk severity.",
    )
    score: float = Field(
        ge=0.0,
        le=1.0,
        description="Normalised risk score [0.0, 1.0] underlying the level label.",
    )
    contributing_factors: list[str] = Field(
        default_factory=list,
        description="Human-readable factors that raised the score, e.g. "
                    "['PII_resource', 'external_destination', 'trajectory_anomaly'].",
    )
    trajectory_anomaly: bool = Field(
        default=False,
        description="True when the TrajectoryEngine flagged this action as part of a "
                    "suspicious sequence.",
    )

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# InjectionResult
# ---------------------------------------------------------------------------


class InjectionResult(BaseModel):
    """
    Output of InjectionDetector.detect(action).

    Produced by: veil/security/injection.py (Yash)
    Consumed by: DecisionEngine (as a trigger for Counter-Agent invocation)
    """

    detected: bool = Field(
        description="True if one or more injection signals were found.",
    )
    signals: list[str] = Field(
        default_factory=list,
        description="Descriptions of specific injection signals detected, e.g. "
                    "['ignore_previous_instructions in purpose', "
                    "'jailbreak_pattern in metadata.user_input'].",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Detector confidence that the signals are genuine injection attempts.",
    )
    source_field: Optional[str] = Field(
        default=None,
        description="The Action field where the primary signal was found, "
                    "e.g. 'purpose', 'metadata', 'resource'.",
    )

    model_config = {"frozen": True}
