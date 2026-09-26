"""
veil/pipeline.py

VEILPipeline — full enforcement pipeline (Sub-Task 10 integration).

Wires all modules in order:
  Interceptor → Classifier (via Normalizer) → CapabilityManager → PolicyEngine
  → TrajectoryEngine → RiskEngine → InjectionDetector
  → (conditional) CounterAgent → JudgeAgent
  → DecisionEngine → Executor → AuditEngine + RevocationEngine

Counter-Agent / Judge are only invoked when:
  - risk_result.level >= HIGH, OR
  - injection_result.detected is True
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from veil.agents.counter import CounterAgent
from veil.agents.decision import DecisionEngine
from veil.agents.judge import JudgeAgent
from veil.agents.revocation import RevocationEngine
from veil.config import settings
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
from veil.security.injection import InjectionDetector
from veil.security.policy import PolicyEngine
from veil.security.risk import RiskEngine
from veil.security.trajectory import TrajectoryEngine
from simulator.client.tools import get_executor_registry

# Risk levels that trigger Counter-Agent + Judge (ordered for comparison)
_RISK_ORDER = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


def _risk_gte(level: RiskLevel, threshold: str) -> bool:
    """Return True if level >= threshold by severity order."""
    try:
        threshold_level = RiskLevel(threshold.upper())
    except ValueError:
        threshold_level = RiskLevel.HIGH
    return _RISK_ORDER.index(level) >= _RISK_ORDER.index(threshold_level)


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

    All intelligence modules default to real implementations. They can be
    overridden via constructor for testing.

    Usage:
        pipeline = VEILPipeline()
        result = pipeline.run(raw_payload)
    """

    def __init__(
        self,
        capability_manager: Optional[CapabilityManager] = None,
        policy_engine: Optional[PolicyEngine] = None,
        audit_engine: Optional[AuditEngine] = None,
        trajectory_engine: Optional[TrajectoryEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
        injection_detector: Optional[InjectionDetector] = None,
        counter_agent: Optional[CounterAgent] = None,
        judge_agent: Optional[JudgeAgent] = None,
        decision_engine: Optional[DecisionEngine] = None,
        revocation_engine: Optional[RevocationEngine] = None,
    ) -> None:
        # RevocationEngine must be created first — shared by CapabilityManager
        self._revocation_engine = revocation_engine or RevocationEngine()

        self._interceptor = ActionInterceptor()
        # Wire revocation store into capability manager
        self._capability_manager = capability_manager or CapabilityManager(
            revocation_store=self._revocation_engine
        )
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_engine = audit_engine or AuditEngine()
        self._executor = ActionExecutor(tool_registry=get_executor_registry())

        # Intelligence layer — all real by default
        self._trajectory_engine = trajectory_engine or TrajectoryEngine()
        self._risk_engine = risk_engine or RiskEngine()
        self._injection_detector = injection_detector or InjectionDetector()
        self._decision_engine = decision_engine or DecisionEngine()

        # LLM agents — None by default; only instantiated on first HIGH/CRITICAL action
        # to avoid loading watsonx credentials for low-risk pipelines
        self._counter_agent = counter_agent  # lazily set if needed
        self._judge_agent = judge_agent      # lazily set if needed

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

        # 2. Capability check (deterministic — consults RevocationEngine)
        capability_result = self._capability_manager.check(action)

        # 3. Policy check (deterministic)
        policy_result = self._policy_engine.evaluate(action, capability_result)

        # 4. Trajectory record + analyze
        self._trajectory_engine.record(action)
        trajectory_analysis = self._trajectory_engine.analyze(action.session_id)

        # 5. Risk scoring — passes trajectory_analysis as 4th arg
        risk_result: RiskResult = self._risk_engine.score(
            action, capability_result, policy_result, trajectory_analysis
        )

        # 6. Injection detection
        injection_result: InjectionResult = self._injection_detector.detect(action)

        # 7. Conditional: Counter-Agent + Judge (only for HIGH/CRITICAL or injection)
        judge_verdict = None
        should_invoke_agents = (
            _risk_gte(risk_result.level, settings.risk_threshold_for_agents)
            or injection_result.detected
        )

        if should_invoke_agents:
            context = {
                "action_count": len(self._trajectory_engine.get_history(action.session_id)),
                "trajectory_anomaly": trajectory_analysis.anomaly_detected,
                "policy_violations": list(policy_result.violated_rules),
            }
            # Lazy-init LLM agents — may raise if watsonx creds not set
            try:
                if self._counter_agent is None:
                    self._counter_agent = CounterAgent()
                if self._judge_agent is None:
                    self._judge_agent = JudgeAgent()

                counter_finding = self._counter_agent.analyze(action, context)
                judge_verdict = self._judge_agent.review(action, counter_finding, context)
            except Exception as e:
                import traceback
                print(f"ERROR: Failed to invoke Groq LLM Agents: {e}")
                traceback.print_exc()
                # LLM unavailable — proceed without agentic analysis
                # The deterministic decision engine will still enforce hard rules
                judge_verdict = None

        # 8. Decision Engine (deterministic — LLM verdict is input, not authority)
        decision_result = self._decision_engine.decide(
            risk_result,
            policy_result,
            capability_result,
            injection_result=injection_result,
            judge_verdict=judge_verdict,
        )

        # 9. If REVOKE decision — register in RevocationEngine for this session
        if decision_result.decision == Decision.REVOKE and decision_result.revoked_capability:
            self._revocation_engine.revoke(
                agent_id=action.agent_id,
                session_id=action.session_id,
                capability=decision_result.revoked_capability,
                reason=decision_result.reason,
            )

        # 10. Execute (gated on ALLOW only)
        execution_result = self._executor.execute(action, decision_result)

        # 11. Audit (always — non-optional)
        self._audit_engine.log(
            action,
            decision_result,
            policy_result=policy_result,
            risk_level=risk_result.level,
            injection_detected=injection_result.detected,
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
