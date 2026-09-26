"""
veil/models/decisions.py

Decision enum and DecisionResult — the final output of the VEIL pipeline.

IMPORTANT: The Decision enum is the enforcement signal. It is produced by the
deterministic DecisionEngine and consumed by the Executor. The LLM is an
advisory input to the DecisionEngine; it never sets this value directly.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Decision(str, Enum):
    """
    Enforcement decision returned by the VEIL pipeline.

    Ordered from least to most severe. The Executor only proceeds on ALLOW.
    """

    ALLOW = "ALLOW"
    """Action is permitted. Executor proceeds."""

    WARN = "WARN"
    """Action is permitted but flagged. Executor proceeds; audit records the warning."""

    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    """Action is held pending human approval. Executor does not proceed."""

    BLOCK = "BLOCK"
    """Action is denied. Executor does not proceed. Session continues."""

    REVOKE = "REVOKE"
    """Action is denied AND the triggering capability is revoked for the session.
    Executor does not proceed. Subsequent capability checks will fail."""


class DecisionResult(BaseModel):
    """
    Full result from the VEIL pipeline for a single Action.

    Consumed by:
    - ActionExecutor (gate check)
    - AuditEngine (logging)
    - Dashboard (visualization)
    - RevocationEngine (when decision == REVOKE)
    """

    decision: Decision = Field(
        description="Enforcement outcome.",
    )
    reason: str = Field(
        description="Human-readable explanation of why this decision was reached. "
                    "Safe to surface in audit logs and the dashboard.",
    )
    triggered_rules: list[str] = Field(
        default_factory=list,
        description="Ordered list of rule identifiers or check names that contributed "
                    "to this decision, e.g. ['capability.denied', 'policy.pii_to_external'].",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score [0.0, 1.0]. Deterministic decisions always yield 1.0. "
                    "LLM-influenced decisions carry the judge's confidence.",
    )
    requires_human_review: bool = Field(
        default=False,
        description="True when the decision is REQUIRE_APPROVAL or when the confidence "
                    "is below the configured threshold. Surfaced in the dashboard.",
    )
    revoked_capability: Optional[str] = Field(
        default=None,
        description="Populated only when decision == REVOKE. The capability token that "
                    "was revoked, e.g. 'http.request'.",
    )

    model_config = {"frozen": True}
