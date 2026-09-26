"""
simulator/client/agents.py

DOOMSDAY CORP agent profiles and scenario runners.

Each agent has:
  - A declared agent_id that matches the CapabilityManager registry.
  - A description of its business purpose.
  - A run_scenario() method that builds and returns Action objects for a
    named scenario. The pipeline caller feeds those Actions into VEIL.
"""

from __future__ import annotations

from typing import Callable

from veil.models.action import Action, DataClassification


def _make_action(agent_id: str, session_id: str, **kwargs) -> Action:
    return Action(agent_id=agent_id, session_id=session_id, **kwargs)


class SupportAgent:
    """
    Customer support agent.
    Allowed: database.read on customer_db, file.read on docs, email.read.
    Prohibited: writes, payment_records, http to external destinations.
    """

    agent_id = "SupportAgent"
    description = "Handles customer inquiries. Read-only access to customer data."

    def run_scenario(self, scenario_name: str, session_id: str = "sess-support-001") -> list[Action]:
        scenarios: dict[str, Callable[[], list[Action]]] = {
            "legitimate_pii_read": lambda: self._legitimate_pii_read(session_id),
        }
        builder = scenarios.get(scenario_name)
        if builder is None:
            raise ValueError(f"Unknown scenario '{scenario_name}' for {self.agent_id}.")
        return builder()

    def _legitimate_pii_read(self, session_id: str) -> list[Action]:
        """Legitimate use: agent reads customer record to answer support query."""
        return [
            _make_action(
                self.agent_id, session_id,
                tool="database",
                operation="read",
                resource="customer_db",
                purpose="Customer requested account details.",
                provenance="user_instruction",
            )
        ]


class ResearchAgent:
    """
    Internal research agent.
    Allowed: file.read on docs, http.request to any URL.
    Prohibited: database writes, PII resources.
    """

    agent_id = "ResearchAgent"
    description = "Conducts research using internal docs and public web."

    def run_scenario(self, scenario_name: str, session_id: str = "sess-research-001") -> list[Action]:
        scenarios: dict[str, Callable[[], list[Action]]] = {
            "legitimate_doc_read": lambda: self._legitimate_doc_read(session_id),
        }
        builder = scenarios.get(scenario_name)
        if builder is None:
            raise ValueError(f"Unknown scenario '{scenario_name}' for {self.agent_id}.")
        return builder()

    def _legitimate_doc_read(self, session_id: str) -> list[Action]:
        return [
            _make_action(
                self.agent_id, session_id,
                tool="file",
                operation="read",
                resource="public_docs",
                purpose="Gathering product information for research report.",
                provenance="agent_plan",
            )
        ]


class FinanceAgent:
    """
    Finance agent.
    Allowed: database.read/write on payment_records, file.read/write on internal_docs.
    Prohibited: customer_db, external HTTP.
    """

    agent_id = "FinanceAgent"
    description = "Processes financial transactions and reports."

    def run_scenario(self, scenario_name: str, session_id: str = "sess-finance-001") -> list[Action]:
        scenarios: dict[str, Callable[[], list[Action]]] = {
            "legitimate_payment_read": lambda: self._legitimate_payment_read(session_id),
        }
        builder = scenarios.get(scenario_name)
        if builder is None:
            raise ValueError(f"Unknown scenario '{scenario_name}' for {self.agent_id}.")
        return builder()

    def _legitimate_payment_read(self, session_id: str) -> list[Action]:
        return [
            _make_action(
                self.agent_id, session_id,
                tool="database",
                operation="read",
                resource="payment_records",
                purpose="Generating monthly financial report.",
                provenance="agent_plan",
            )
        ]
