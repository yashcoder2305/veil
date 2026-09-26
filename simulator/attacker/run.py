"""
simulator/attacker/run.py

Entry point for the attacker simulator.

Usage:
    python -m simulator.attacker.run [--scenario SCENARIO_NAME] [--list]

Available scenarios:
    PROMPT_INJECTION
    PII_EXFIL_CHAIN
    PRIVILEGE_ABUSE
    P0_MULTI_STEP_ATTACK  (default)

This script feeds the generated Action sequences directly through the
VEIL intelligence layer (trajectory + risk + injection + decision) so you
can see what VEIL detects without needing the full pipeline wired up.
"""

from __future__ import annotations

import argparse
import json
import sys

from simulator.attacker.scenarios import (
    MultiStepChain,
    PiiExfiltrationChain,
    PrivilegeAbuseScenario,
    PromptInjectionScenario,
)
from veil.models.results import CapabilityResult, PolicyResult, RiskLevel
from veil.security.injection import InjectionDetector
from veil.security.risk import RiskEngine
from veil.security.trajectory import TrajectoryEngine
from veil.agents.decision import DecisionEngine


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

SCENARIOS = {
    "PROMPT_INJECTION": PromptInjectionScenario(),
    "PII_EXFIL_CHAIN": PiiExfiltrationChain(),
    "PRIVILEGE_ABUSE": PrivilegeAbuseScenario(),
    "P0_MULTI_STEP_ATTACK": MultiStepChain(),
}


# ---------------------------------------------------------------------------
# Minimal context objects (stand-ins until full pipeline is wired)
# ---------------------------------------------------------------------------


def _make_capability_result(action, denied: bool = False) -> CapabilityResult:
    """Stub: PRIVILEGE_ABUSE scenario explicitly denies shell.execute."""
    is_denied = denied or (action.tool == "shell" and action.operation == "execute")
    return CapabilityResult(
        allowed=not is_denied,
        agent_id=action.agent_id,
        requested_capability=action.requested_capability or f"{action.tool}.{action.operation}",
        reason="PrivilegeAbuse: shell.execute not granted" if is_denied else "Stub: allowed",
        is_revoked=False,
    )


def _make_policy_result(action) -> PolicyResult:
    """Stub: any external destination with sensitive data is a policy violation."""
    if (
        action.destination
        and action.destination.startswith("http")
        and action.data_classification.value in ("PII", "FINANCIAL", "SECRET", "CREDENTIAL")
    ):
        return PolicyResult(
            passed=False,
            violated_rules=["POLICY_PII_TO_EXTERNAL"],
            reason="Sensitive data destined for external HTTP endpoint.",
            requires_escalation=False,
        )
    return PolicyResult(passed=True, violated_rules=[], reason="No policy violations.")


# ---------------------------------------------------------------------------
# Run a scenario
# ---------------------------------------------------------------------------


def run_scenario(name: str) -> None:
    scenario = SCENARIOS[name]
    print(f"\n{'='*60}")
    print(f"  SCENARIO: {scenario.name}")
    print(f"  {scenario.description}")
    print(f"{'='*60}\n")

    actions = scenario.generate()
    trajectory = TrajectoryEngine()
    risk_engine = RiskEngine()
    injection_detector = InjectionDetector()
    decision_engine = DecisionEngine()

    for i, action in enumerate(actions, start=1):
        print(f"  Step {i}: {action.tool}.{action.operation} -> {action.resource}")
        if action.destination:
            print(f"           destination: {action.destination}")

        # Record in trajectory
        trajectory.record(action)
        traj_analysis = trajectory.analyze(action.session_id)

        # Get stubs for capability and policy
        cap_result = _make_capability_result(action)
        pol_result = _make_policy_result(action)

        # Score risk
        risk_result = risk_engine.score(action, cap_result, pol_result, traj_analysis)

        # Detect injection
        inj_result = injection_detector.detect(action)

        # Make decision
        decision_result = decision_engine.decide(
            risk_result, pol_result, cap_result, inj_result
        )

        # Report
        print(f"  ┌─ Risk:     {risk_result.level.value} ({risk_result.score:.2f})")
        if risk_result.contributing_factors:
            print(f"  │  Factors:  {', '.join(risk_result.contributing_factors[:3])}")
        if inj_result.detected:
            print(f"  │  Injection: {', '.join(inj_result.signals[:2])}")
        if traj_analysis.anomaly_detected:
            print(f"  │  Trajectory: {traj_analysis.pattern_name} — {traj_analysis.description}")
        print(f"  └─ Decision: {decision_result.decision.value}")
        print(f"     Reason:   {decision_result.reason}")
        if decision_result.triggered_rules:
            print(f"     Rules:    {', '.join(decision_result.triggered_rules[:4])}")
        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VEIL Attacker Simulator — feeds attack scenarios through the intelligence layer."
    )
    parser.add_argument(
        "--scenario",
        default="P0_MULTI_STEP_ATTACK",
        choices=list(SCENARIOS.keys()),
        help="Which attack scenario to run (default: P0_MULTI_STEP_ATTACK).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available scenarios and exit.",
    )
    args = parser.parse_args()

    if args.list:
        print("\nAvailable scenarios:")
        for name, s in SCENARIOS.items():
            print(f"  {name:30s}  {s.description}")
        print()
        sys.exit(0)

    run_scenario(args.scenario)


if __name__ == "__main__":
    main()
