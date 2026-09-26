"""
veil/pipeline.py

VEILPipeline — deterministic enforcement pipeline (Durga's layers only).

This is the Sub-Task 10 integration target. Right now it wires:
  Interceptor → Classifier (via Normalizer) → CapabilityManager → PolicyEngine
  → DecisionEngine (stub) → Executor → AuditEngine

Yash's layers (TrajectoryEngine, RiskEngine, InjectionDetector, CounterAgent,
JudgeAgent, RevocationEngine) will be wired in during Sub-Task 10 integration.
The method signatures and slot positions are already in place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from veil.gateway.executor import ActionExecutor, ExecutionResult
from veil.gateway.interceptor import ActionInterceptor
from veil.memory.audit import AuditEngine
from veil.models.action import Action
from veil.models.decisions import Decision, DecisionResult
from veil.models.results import (
    CapabilityResult,
    InjectionResult,
    PolicyResult,
    RiskLevel,
    RiskResult,
)
from veil.security.capabilities import CapabilityManager
from veil.security.policy import PolicyEngine
from simulator.client.tools import get_executor_registry


@dataclass
class PipelineResult:
    """Full result of a single pipeline run."""
    action: Action
    capability_result: CapabilityResult
    policy_result: PolicyResult
    risk_result: Optional[RiskResult]
    injection_result: Optional[InjectionResult]
    decision_result: DecisionResult
    execution_result: ExecutionResult


class VEILPipeline:
    """
    Orchestrates the full VEIL enforcement pipeline for a single Action.

    Deterministic layers always run. Intelligence layers (Yash) are injected
    via constructor — if not provided, safe stubs are used so the pipeline
    runs end-to-end without them.

    Usage:
        pipeline = VEILPipeline()
        result = pipeline.run(raw_payload)
    """

    def __init__(
        self,
        capability_manager: Optional[CapabilityManager] = None,
        policy_engine: Optional[PolicyEngine] = None,
        audit_engine: Optional[AuditEngine] = None,
        # Yash's modules will be injected here during Sub-Task 10:
        trajectory_engine: Optional[Any] = None,
        risk_engine: Optional[Any] = None,
        injection_detector: Optional[Any] = None,
        counter_agent: Optional[Any] = None,
        judge_agent: Optional[Any] = None,
        decision_engine: Optional[Any] = None,
        revocation_engine: Optional[Any] = None,
    ) -> None:
        self._interceptor = ActionInterceptor()
        self._capability_manager = capability_manager or CapabilityManager()
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_engine = audit_engine or AuditEngine()
        self._executor = ActionExecutor(tool_registry=get_executor_registry())

        # Intelligence layer slots (None = not yet wired)
        self._trajectory_engine = trajectory_engine
        self._risk_engine = risk_engine
        self._injection_detector = injection_detector
        self._counter_agent = counter_agent
        self._judge_agent = judge_agent
        self._decision_engine = decision_engine
        self._revocation_engine = revocation_engine

    def run(self, raw_payload: Any) -> PipelineResult:
        """
        Run a raw tool-call payload through the full VEIL pipeline.

        Args:
            raw_payload: Raw dict from agent framework.

        Returns:
            PipelineResult containing all intermediate and final results.
        """
        # 1. Intercept + Normalize
        action = self._interceptor.intercept(raw_payload)

        # 2. Capability check (deterministic)
        capability_result = self._capability_manager.check(action)

        # 3. Policy check (deterministic)
        policy_result = self._policy_engine.evaluate(action, capability_result)

        # 4. Trajectory record (Yash) — slot, no-op if not wired
        if self._trajectory_engine is not None:
            self._trajectory_engine.record(action)

        # 5. Risk scoring (Yash) — stub result if not wired
        risk_result: Optional[RiskResult] = None
        if self._risk_engine is not None:
            risk_result = self._risk_engine.score(action, capability_result, policy_result)

        # 6. Injection detection (Yash) — stub result if not wired
        injection_result: Optional[InjectionResult] = None
        if self._injection_detector is not None:
            injection_result = self._injection_detector.detect(action)

        # 7. Decision — use Yash's engine if wired, else deterministic stub
        if self._decision_engine is not None:
            decision_result = self._decision_engine.decide(
                risk_result, policy_result, capability_result,
                injection_result=injection_result,
            )
        else:
            decision_result = self._deterministic_decision(
                capability_result, policy_result
            )

        # 8. Execute (gated on ALLOW)
        execution_result = self._executor.execute(action, decision_result)

        # 9. Audit (always — non-optional)
        self._audit_engine.log(
            action,
            decision_result,
            policy_result=policy_result,
            risk_level=risk_result.level if risk_result else RiskLevel.NONE,
            injection_detected=injection_result.detected if injection_result else False,
        )

        return PipelineResult(
            action=action,
            capability_result=capability_result,
            policy_result=policy_result,
            risk_result=risk_result,
            injection_result=injection_result,
            decision_result=decision_result,
            execution_result=execution_result,
        )

    # -----------------------------------------------------------------------
    # Deterministic decision stub — used until Yash's DecisionEngine is wired
    # -----------------------------------------------------------------------

    def _deterministic_decision(
        self,
        capability_result: CapabilityResult,
        policy_result: PolicyResult,
    ) -> DecisionResult:
        """
        Minimal deterministic decision logic.

        Rule:
          - Capability denied OR hard policy violation → BLOCK
          - Revoked capability → REVOKE
          - Policy escalation only → WARN
          - Everything else → ALLOW
        """
        triggered = list(policy_result.violated_rules)

        if capability_result.is_revoked:
            return DecisionResult(
                decision=Decision.REVOKE,
                reason=capability_result.reason,
                triggered_rules=[capability_result.requested_capability],
                confidence=1.0,
                revoked_capability=capability_result.requested_capability,
            )

        if not capability_result.allowed or not policy_result.passed:
            reason = (
                policy_result.reason
                if not policy_result.passed
                else capability_result.reason
            )
            return DecisionResult(
                decision=Decision.BLOCK,
                reason=reason,
                triggered_rules=triggered or [capability_result.requested_capability],
                confidence=1.0,
            )

        if policy_result.requires_escalation:
            return DecisionResult(
                decision=Decision.WARN,
                reason=f"Escalation triggered: {policy_result.reason}",
                triggered_rules=triggered,
                confidence=1.0,
                requires_human_review=True,
            )

        return DecisionResult(
            decision=Decision.ALLOW,
            reason="All deterministic checks passed.",
            triggered_rules=[],
            confidence=1.0,
        )
