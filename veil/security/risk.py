"""
veil/security/risk.py

RiskEngine — weighted combination of all security signals into a single
normalised risk score and level. No LLM calls; deterministic maths only.

Score weights (sum = 1.0):
  capability_risk     0.25
  data_sensitivity    0.25
  destination_risk    0.20
  policy_violation    0.20
  trajectory_anomaly  0.10
"""

from __future__ import annotations

from veil.models.action import Action, DataClassification
from veil.models.results import (
    CapabilityResult,
    PolicyResult,
    RiskLevel,
    RiskResult,
)
from veil.security.trajectory import TrajectoryAnalysis

# ---------------------------------------------------------------------------
# Scoring tables
# ---------------------------------------------------------------------------

_CLASSIFICATION_SCORE: dict[DataClassification, float] = {
    DataClassification.PUBLIC:       0.0,
    DataClassification.INTERNAL:     0.2,
    DataClassification.CONFIDENTIAL: 0.5,
    DataClassification.PII:          0.8,
    DataClassification.FINANCIAL:    0.8,
    DataClassification.SECRET:       1.0,
    DataClassification.CREDENTIAL:   1.0,
    DataClassification.UNKNOWN:      0.3,
}

_DANGEROUS_OPS = {"execute", "delete", "drop", "format", "shell", "write"}
_EXTERNAL_KEYWORDS = {"http", "ftp", "smtp", "external", "webhook", "transfer"}


def _capability_risk(cap: CapabilityResult) -> float:
    """Denied capability or revoked capability → high risk."""
    if cap.is_revoked:
        return 1.0
    if not cap.allowed:
        return 0.8
    return 0.0


def _data_sensitivity(action: Action) -> float:
    return _CLASSIFICATION_SCORE.get(action.data_classification, 0.3)


def _destination_risk(action: Action) -> float:
    dest = action.destination.lower()
    if not dest:
        return 0.0
    if any(kw in dest for kw in _EXTERNAL_KEYWORDS):
        return 0.9
    return 0.3


def _operation_risk(action: Action) -> float:
    return 0.6 if action.operation.lower() in _DANGEROUS_OPS else 0.0


def _policy_risk(policy: PolicyResult) -> float:
    if not policy.passed:
        return 0.9 if policy.requires_escalation else 0.7
    return 0.0


def _trajectory_risk(trajectory: TrajectoryAnalysis) -> float:
    return 1.0 if trajectory.anomaly_detected else 0.0


def _level_from_score(score: float) -> RiskLevel:
    if score < 0.20:
        return RiskLevel.NONE
    if score < 0.40:
        return RiskLevel.LOW
    if score < 0.60:
        return RiskLevel.MEDIUM
    if score < 0.80:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# RiskEngine
# ---------------------------------------------------------------------------


class RiskEngine:
    """
    Produces a RiskResult by combining all upstream signals.

    Inputs:
      action             — the normalised Action
      capability_result  — from CapabilityManager.check()
      policy_result      — from PolicyEngine.evaluate()
      trajectory_analysis— from TrajectoryEngine.analyze()
    """

    def score(
        self,
        action: Action,
        capability_result: CapabilityResult,
        policy_result: PolicyResult,
        trajectory_analysis: TrajectoryAnalysis,
    ) -> RiskResult:
        factors: list[str] = []

        cap_score = _capability_risk(capability_result)
        data_score = _data_sensitivity(action)
        dest_score = _destination_risk(action)
        op_score = _operation_risk(action)
        policy_score = _policy_risk(policy_result)
        traj_score = _trajectory_risk(trajectory_analysis)

        # Merge op_score into policy_score channel (both capped at policy weight)
        combined_policy = min(1.0, max(policy_score, op_score))

        weighted = (
            0.25 * cap_score
            + 0.25 * data_score
            + 0.20 * dest_score
            + 0.20 * combined_policy
            + 0.10 * traj_score
        )
        final_score = min(1.0, round(weighted, 4))

        # Build human-readable contributing factors
        if cap_score > 0:
            factors.append(
                "revoked_capability" if capability_result.is_revoked else "capability_denied"
            )
        if data_score >= 0.8:
            factors.append(f"sensitive_resource:{action.data_classification.value}")
        elif data_score >= 0.5:
            factors.append(f"confidential_resource:{action.data_classification.value}")
        if dest_score >= 0.9:
            factors.append("external_destination")
        if op_score > 0:
            factors.append(f"dangerous_operation:{action.operation}")
        if policy_score > 0:
            factors.extend(policy_result.violated_rules)
        if traj_score > 0:
            factors.append(f"trajectory_anomaly:{trajectory_analysis.pattern_name}")

        return RiskResult(
            level=_level_from_score(final_score),
            score=final_score,
            contributing_factors=factors,
            trajectory_anomaly=trajectory_analysis.anomaly_detected,
        )
