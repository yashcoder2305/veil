"""
veil/agents/judge.py

JudgeAgent — Groq-backed verdict engine.

The JudgeAgent receives the CounterAgent's abuse finding and reviews it
against the agent's declared goal and granted permissions. It returns a
structured verdict with a confidence score.

The JudgeAgent's output is *advisory*. The deterministic DecisionEngine
always has the final say — a deterministic BLOCK cannot be overridden.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

from veil.config import settings


# ---------------------------------------------------------------------------
# JudgeVerdict — output type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JudgeVerdict:
    """Structured verdict returned by JudgeAgent.review()."""

    upheld: bool
    """True if the counter-agent's concern is upheld (action should be restricted)."""

    confidence: float
    """[0.0, 1.0] — how certain the judge is in its verdict."""

    reasoning: str
    """Human-readable justification for the verdict."""

    recommended_decision: str
    """One of: 'ALLOW', 'WARN', 'REQUIRE_APPROVAL', 'BLOCK', 'REVOKE'."""

    raw_response: Optional[str] = None
    """Raw LLM response, truncated to 2000 chars for the audit trail."""


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are VEIL-JudgeAgent, an impartial AI security judge. "
    "You review a security concern raised by a counter-agent and decide whether it is valid "
    "given the agent's declared goal and granted permissions. "
    "Output ONLY the JSON object requested — no markdown fences, no commentary."
)

_USER_TEMPLATE = """\
Agent ID: {agent_id}
Agent declared goal: {declared_goal}
Granted capabilities: {granted_capabilities}

Action under review:
  Tool: {tool}
  Operation: {operation}
  Resource: {resource}
  Destination: {destination}
  Data classification: {data_classification}
  Declared purpose: {purpose}

Counter-agent finding:
  Abuse scenario: {abuse_scenario}
  Severity: {severity}
  Risk indicators: {risk_indicators}
  Counter-agent recommendation: {counter_recommendation}

Is the counter-agent's concern valid given the agent's goal and permissions?
Respond with a JSON object with exactly these keys:
{{
  "upheld": true|false,
  "confidence": 0.0-1.0,
  "reasoning": "<string>",
  "recommended_decision": "ALLOW|WARN|REQUIRE_APPROVAL|BLOCK|REVOKE"
}}
"""


def _build_messages(action, counter_finding, context: dict) -> list[dict]:
    user_msg = _USER_TEMPLATE.format(
        agent_id=action.agent_id,
        declared_goal=context.get("declared_goal", "(unknown)"),
        granted_capabilities=", ".join(context.get("granted_capabilities", [])) or "(none)",
        tool=action.tool,
        operation=action.operation,
        resource=action.resource,
        destination=action.destination or "(none)",
        data_classification=action.data_classification.value,
        purpose=action.purpose or "(none)",
        abuse_scenario=counter_finding.abuse_scenario,
        severity=counter_finding.severity_assessment,
        risk_indicators=", ".join(counter_finding.risk_indicators) or "(none)",
        counter_recommendation=counter_finding.recommendation,
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_msg},
    ]


def _parse_verdict(raw: str) -> dict:
    """Extract a JSON object from raw LLM output."""
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
# JudgeAgent
# ---------------------------------------------------------------------------


class JudgeAgent:
    """
    Reviews the CounterAgent's finding and returns a JudgeVerdict.

    Falls back to a conservative uphold if the LLM is unavailable.
    """

    def __init__(self) -> None:
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from groq import Groq
                self._client = Groq(api_key=settings.groq_api_key)
            except Exception as exc:
                raise RuntimeError(
                    f"JudgeAgent: failed to initialise Groq client: {exc}"
                ) from exc
        return self._client

    def review(self, action, counter_finding, context: dict) -> JudgeVerdict:
        """
        Review *counter_finding* against *action* and return a JudgeVerdict.

        context keys (all optional):
          declared_goal         str   — agent's stated purpose
          granted_capabilities  list  — capability tokens granted to agent
        """
        messages = _build_messages(action, counter_finding, context)

        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=settings.groq_model_id,
                messages=messages,
                max_tokens=512,
                temperature=0.1,
            )
            raw = response.choices[0].message.content or ""
        except Exception as exc:
            # LLM unavailable — fail safe: uphold the concern
            return JudgeVerdict(
                upheld=True,
                confidence=0.5,
                reasoning=f"LLM unavailable ({exc}); conservative uphold applied.",
                recommended_decision="BLOCK",
                raw_response=None,
            )

        parsed = _parse_verdict(raw)

        upheld = bool(parsed.get("upheld", True))
        try:
            confidence = float(parsed.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.5

        return JudgeVerdict(
            upheld=upheld,
            confidence=round(confidence, 3),
            reasoning=parsed.get("reasoning", "No reasoning provided."),
            recommended_decision=parsed.get("recommended_decision", "BLOCK"),
            raw_response=raw[:2000],
        )
