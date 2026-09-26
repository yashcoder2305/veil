"""
veil/agents/counter.py

CounterAgent — Groq-backed adversarial analysis.

Given an Action and its surrounding context, the CounterAgent constructs
plausible abuse scenarios: "What could a malicious agent do with this action?"

Only invoked for HIGH / CRITICAL risk actions or when injection is detected.
Never receives raw customer data — metadata only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

from veil.config import settings


# ---------------------------------------------------------------------------
# CounterAgentFinding — output type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CounterAgentFinding:
    """Structured output produced by the CounterAgent."""

    abuse_scenario: str
    """Human-readable description of the most plausible abuse path."""

    risk_indicators: list[str]
    """Specific observable indicators that support the abuse scenario."""

    severity_assessment: str
    """One of: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'"""

    recommendation: str
    """Suggested enforcement action: 'ALLOW', 'WARN', 'BLOCK', 'REVOKE'."""

    raw_response: Optional[str] = None
    """The raw LLM response, stored for audit trail. Truncated to 2000 chars."""


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are VEIL-CounterAgent, an adversarial AI security analyst. "
    "Your job is to identify how a malicious actor could abuse the described agent action. "
    "Be concise and precise. Output ONLY the JSON object requested — no markdown fences. "
    "Never include raw personal data in your response."
)

_USER_TEMPLATE = """\
Analyze this agent action for potential abuse:

Agent ID: {agent_id}
Tool: {tool}
Operation: {operation}
Resource: {resource}
Destination: {destination}
Data Classification: {data_classification}
Declared Purpose: {purpose}
Provenance: {provenance}
Session action count: {action_count}
Recent trajectory anomaly: {trajectory_anomaly}
Policy violations: {policy_violations}

Respond with a JSON object with exactly these keys:
{{
  "abuse_scenario": "<string>",
  "risk_indicators": ["<string>", ...],
  "severity_assessment": "LOW|MEDIUM|HIGH|CRITICAL",
  "recommendation": "ALLOW|WARN|BLOCK|REVOKE"
}}
"""


def _build_messages(action, context: dict) -> list[dict]:
    user_msg = _USER_TEMPLATE.format(
        agent_id=action.agent_id,
        tool=action.tool,
        operation=action.operation,
        resource=action.resource,
        destination=action.destination or "(none)",
        data_classification=action.data_classification.value,
        purpose=action.purpose or "(none)",
        provenance=action.provenance or "(none)",
        action_count=context.get("action_count", "unknown"),
        trajectory_anomaly=context.get("trajectory_anomaly", False),
        policy_violations=", ".join(context.get("policy_violations", [])) or "(none)",
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_msg},
    ]


# ---------------------------------------------------------------------------
# Fallback parser — extract JSON from messy LLM output
# ---------------------------------------------------------------------------


def _parse_finding(raw: str) -> dict:
    """Try to extract a JSON object from the raw LLM response."""
    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return {}


# ---------------------------------------------------------------------------
# CounterAgent
# ---------------------------------------------------------------------------


class CounterAgent:
    """
    Calls Groq (Llama 3) to generate an adversarial analysis of a high-risk action.

    Falls back gracefully if the LLM is unavailable — returns a conservative
    BLOCK recommendation so the pipeline stays safe.
    """

    def __init__(self) -> None:
        self._client = None  # lazily initialised

    def _get_client(self):
        if self._client is None:
            try:
                from groq import Groq
                self._client = Groq(api_key=settings.groq_api_key)
            except Exception as exc:
                raise RuntimeError(
                    f"CounterAgent: failed to initialise Groq client: {exc}"
                ) from exc
        return self._client

    def analyze(self, action, context: dict) -> CounterAgentFinding:
        """
        Produce a CounterAgentFinding for *action* using the given context dict.

        context keys (all optional):
          action_count        int   — number of actions in this session so far
          trajectory_anomaly  bool  — TrajectoryEngine flagged a pattern
          policy_violations   list  — violated rule identifiers
        """
        messages = _build_messages(action, context)

        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=settings.groq_model_id,
                messages=messages,
                max_tokens=512,
                temperature=0.2,
            )
            raw = response.choices[0].message.content or ""
        except Exception as exc:
            # LLM unavailable — fail safe
            return CounterAgentFinding(
                abuse_scenario=f"LLM unavailable ({exc}); conservative BLOCK applied.",
                risk_indicators=["llm_call_failed"],
                severity_assessment="HIGH",
                recommendation="BLOCK",
                raw_response=None,
            )

        parsed = _parse_finding(raw)
        return CounterAgentFinding(
            abuse_scenario=parsed.get("abuse_scenario", "Unable to parse scenario."),
            risk_indicators=parsed.get("risk_indicators", []),
            severity_assessment=parsed.get("severity_assessment", "HIGH"),
            recommendation=parsed.get("recommendation", "BLOCK"),
            raw_response=raw[:2000],
        )
