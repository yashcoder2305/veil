"""
simulator/client/run.py

DOOMSDAY CORP scenario runner.

Feeds named scenarios through the VEIL pipeline and prints results.

Usage:
    python simulator/client/run.py --scenario p0_attack
    python simulator/client/run.py --scenario support_legitimate
    python simulator/client/run.py --list
"""

from __future__ import annotations

import argparse
import json
import sys

from simulator.client.scenarios import SCENARIOS
from veil.pipeline import VEILPipeline


def _print_step(step: int, result) -> None:
    action = result.action
    decision = result.decision_result
    execution = result.execution_result

    status_icon = {
        "ALLOW":            "[ALLOW]",
        "WARN":             "[WARN] ",
        "REQUIRE_APPROVAL": "[HOLD] ",
        "BLOCK":            "[BLOCK]",
        "REVOKE":           "[REVOKE]",
    }.get(decision.decision.value, "[?]")

    print(f"\n  Step {step}: {action.tool}.{action.operation} on '{action.resource}'")
    print(f"  Agent    : {action.agent_id} | Session: {action.session_id}")
    print(f"  Decision : {status_icon} {decision.decision.value}")
    print(f"  Reason   : {decision.reason}")
    if decision.triggered_rules:
        print(f"  Rules    : {', '.join(decision.triggered_rules)}")
    if decision.revoked_capability:
        print(f"  REVOKED  : {decision.revoked_capability}")
    print(f"  Executed : {'yes' if execution.executed else 'no'}")
    if result.policy_result and result.policy_result.violated_rules:
        print(f"  Policy   : {', '.join(result.policy_result.violated_rules)}")


def run_scenario(name: str) -> None:
    if name not in SCENARIOS:
        print(f"Unknown scenario: '{name}'")
        print(f"Available: {', '.join(SCENARIOS)}")
        sys.exit(1)

    actions = SCENARIOS[name]()
    pipeline = VEILPipeline()

    print(f"\n{'='*60}")
    print(f"  VEIL Simulator — Scenario: {name}")
    print(f"  Actions: {len(actions)}")
    print(f"{'='*60}")

    has_block = False
    has_revoke = False

    for i, action in enumerate(actions, start=1):
        # Pipeline expects a raw dict — serialize the Action back to dict
        raw_payload = action.model_dump()
        # Remove action_id and timestamp so interceptor generates fresh ones
        raw_payload.pop("action_id", None)
        raw_payload.pop("timestamp", None)
        # Restore data_classification as string for normalizer
        raw_payload["data_classification"] = action.data_classification.value

        result = pipeline.run(raw_payload)
        _print_step(i, result)

        if result.decision_result.decision.value == "BLOCK":
            has_block = True
        if result.decision_result.decision.value == "REVOKE":
            has_revoke = True

    print(f"\n{'='*60}")
    print(f"  Summary")
    print(f"  BLOCK detected : {'YES' if has_block else 'no'}")
    print(f"  REVOKE detected: {'YES' if has_revoke else 'no'}")
    print(f"  Audit file     : {pipeline._audit_engine._path}")
    print(f"{'='*60}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="VEIL DOOMSDAY CORP Simulator")
    parser.add_argument("--scenario", help="Scenario name to run")
    parser.add_argument("--list", action="store_true", help="List available scenarios")
    args = parser.parse_args()

    if args.list or not args.scenario:
        print("Available scenarios:")
        for name in SCENARIOS:
            print(f"  {name}")
        return

    run_scenario(args.scenario)


if __name__ == "__main__":
    main()
