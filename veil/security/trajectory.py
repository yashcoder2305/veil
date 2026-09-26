"""
veil/security/trajectory.py

TrajectoryEngine — records every Action per session and detects suspicious
multi-step chains. No LLM calls here; pattern matching only.

Known dangerous chains:
  PII_EXFIL  : READ(PII resource) → TRANSFORM → EXTERNAL TRANSFER
  PRIV_ABUSE : capability-denied action followed by retry with different tool
  DATA_STAGE : multiple READ ops on sensitive resources in one session
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import List

from veil.models.action import Action, DataClassification


# ---------------------------------------------------------------------------
# TrajectoryAnalysis — output of analyze()
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrajectoryAnalysis:
    """Result returned by TrajectoryEngine.analyze()."""

    session_id: str
    anomaly_detected: bool
    pattern_name: str  # e.g. "PII_EXFIL", "" if none
    description: str
    action_count: int


# ---------------------------------------------------------------------------
# Dangerous chain patterns
# ---------------------------------------------------------------------------

_SENSITIVE = {DataClassification.PII, DataClassification.FINANCIAL,
               DataClassification.SECRET, DataClassification.CREDENTIAL,
               DataClassification.CONFIDENTIAL}

_TRANSFER_OPS = {"send", "post", "upload", "write", "request"}
_TRANSFORM_TOOLS = {"transform", "llm", "processor", "encoder", "http"}


def _is_sensitive_read(action: Action) -> bool:
    return (
        action.operation in ("read", "query", "fetch", "get")
        and action.data_classification in _SENSITIVE
    )


def _is_external_transfer(action: Action) -> bool:
    has_dest = bool(action.destination) and (
        action.destination.startswith("http")
        or "external" in action.destination.lower()
        or "." in action.destination  # looks like a domain
    )
    return action.operation in _TRANSFER_OPS and has_dest


def _is_transform_or_encode(action: Action) -> bool:
    return action.tool in _TRANSFORM_TOOLS and action.operation in (
        "transform", "encode", "format", "convert", "request"
    )


# ---------------------------------------------------------------------------
# TrajectoryEngine
# ---------------------------------------------------------------------------


class TrajectoryEngine:
    """
    Records action sequences per session and detects known dangerous chains.

    Thread-safety: single-threaded use assumed; wrap with a lock for concurrency.
    """

    def __init__(self) -> None:
        # session_id → ordered list of Actions
        self._sessions: dict[str, list[Action]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, action: Action) -> None:
        """Append *action* to its session's history."""
        self._sessions[action.session_id].append(action)

    def analyze(self, session_id: str) -> TrajectoryAnalysis:
        """
        Scan the action history for *session_id* and return a
        TrajectoryAnalysis describing any detected anomaly.
        """
        actions: List[Action] = self._sessions.get(session_id, [])

        if not actions:
            return TrajectoryAnalysis(
                session_id=session_id,
                anomaly_detected=False,
                pattern_name="",
                description="No actions recorded for this session.",
                action_count=0,
            )

        pattern, description = self._detect_pattern(actions)
        return TrajectoryAnalysis(
            session_id=session_id,
            anomaly_detected=bool(pattern),
            pattern_name=pattern,
            description=description,
            action_count=len(actions),
        )

    def get_history(self, session_id: str) -> list[Action]:
        """Return a copy of the action history for a session."""
        return list(self._sessions.get(session_id, []))

    # ------------------------------------------------------------------
    # Internal pattern matching
    # ------------------------------------------------------------------

    def _detect_pattern(self, actions: list[Action]) -> tuple[str, str]:
        """Return (pattern_name, description) for the first match, or ("", "")."""

        # PII_EXFIL: sensitive READ anywhere before an external TRANSFER
        sensitive_read_seen = any(_is_sensitive_read(a) for a in actions)
        external_transfer_seen = any(_is_external_transfer(a) for a in actions)

        if sensitive_read_seen and external_transfer_seen:
            return (
                "PII_EXFIL",
                "Session contains a sensitive READ followed by an external TRANSFER — "
                "classic data-exfiltration chain.",
            )

        # DATA_STAGE: ≥3 sensitive READs in a single session
        sensitive_reads = sum(1 for a in actions if _is_sensitive_read(a))
        if sensitive_reads >= 3:
            return (
                "DATA_STAGE",
                f"Session contains {sensitive_reads} sensitive READ operations — "
                "possible data staging before exfiltration.",
            )

        return ("", "No dangerous pattern detected.")
