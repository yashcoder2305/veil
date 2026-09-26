"""
veil/memory/feedback.py

FeedbackEngine — validates and routes human/system feedback into threat memory.

No automatic LLM retraining. Feedback updates the threat knowledge base only
after sanitization checks pass.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from veil.config import settings
from veil.memory.threats import ThreatMemory, ThreatPattern


# ---------------------------------------------------------------------------
# FeedbackType
# ---------------------------------------------------------------------------


class FeedbackType(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    """A VEIL block/warn was correct — threat pattern should be reinforced."""

    FALSE_POSITIVE = "FALSE_POSITIVE"
    """VEIL incorrectly flagged a legitimate action — note for tuning."""

    NEW_PATTERN = "NEW_PATTERN"
    """Human analyst submits a novel attack pattern not previously observed."""

    SEVERITY_CORRECTION = "SEVERITY_CORRECTION"
    """The severity label on an existing pattern was wrong."""


# ---------------------------------------------------------------------------
# FeedbackRecord model
# ---------------------------------------------------------------------------


class FeedbackRecord(BaseModel):
    """
    A single feedback submission. Stored for traceability before any update
    is applied to threat memory.
    """

    feedback_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this feedback submission.",
    )
    feedback_type: FeedbackType = Field(
        description="Classification of the feedback.",
    )
    submitted_by: str = Field(
        description="Identifier of the human analyst or system submitting feedback.",
    )
    submitted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of submission.",
    )
    pattern_type: str = Field(
        description="The attack pattern type this feedback pertains to.",
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Structural indicators (sanitized — no raw data).",
    )
    severity: str = Field(
        default="MEDIUM",
        description="Asserted severity: LOW, MEDIUM, HIGH, CRITICAL.",
    )
    notes: str = Field(
        default="",
        description="Free-text analyst notes. Must not contain raw PII.",
    )
    action_id: Optional[str] = Field(
        default=None,
        description="If this feedback relates to a specific action, its action_id.",
    )
    accepted: bool = Field(
        default=False,
        description="Set to True after FeedbackEngine validates and applies this record.",
    )
    rejection_reason: str = Field(
        default="",
        description="Populated if the feedback failed validation.",
    )

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_VALID_PATTERN_TYPES = {
    "PII_EXFIL", "PROMPT_INJECTION", "PRIVILEGE_ABUSE",
    "DATA_STAGE", "CREDENTIAL_ACCESS", "LATERAL_MOVEMENT",
    "MULTI_STEP_ATTACK", "UNKNOWN",
}

# Substrings that suggest raw data was accidentally included
_RAW_DATA_SIGNALS = [
    "SELECT", "INSERT", "UPDATE", "DELETE",
    "@gmail", "@yahoo", "ssn:", "password:", "token:",
    "credit_card", "cvv",
]


def _contains_raw_data(text: str) -> bool:
    lowered = text.lower()
    return any(sig.lower() in lowered for sig in _RAW_DATA_SIGNALS)


def _validate(record: FeedbackRecord) -> Optional[str]:
    """Return a rejection reason string, or None if valid."""
    if record.severity.upper() not in _VALID_SEVERITIES:
        return f"Invalid severity '{record.severity}'. Must be one of {_VALID_SEVERITIES}."
    if not record.indicators:
        return "Feedback must include at least one structural indicator."
    if _contains_raw_data(record.notes):
        return "Feedback notes appear to contain raw data. Remove any PII or credentials."
    for ind in record.indicators:
        if _contains_raw_data(ind):
            return f"Indicator '{ind[:40]}' appears to contain raw data."
    return None


# ---------------------------------------------------------------------------
# FeedbackEngine
# ---------------------------------------------------------------------------


class FeedbackEngine:
    """
    Validates incoming feedback and, if accepted, writes a ThreatPattern to
    the ThreatMemory store.

    Never triggers automatic model retraining.
    """

    def __init__(
        self,
        threat_memory: ThreatMemory | None = None,
        feedback_log_path: Path | None = None,
    ) -> None:
        self._memory = threat_memory or ThreatMemory()
        self._log_path = (
            Path(feedback_log_path)
            if feedback_log_path
            else settings.threat_memory_path.parent / "feedback.jsonl"
        )
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit(self, feedback: FeedbackRecord) -> FeedbackRecord:
        """
        Validate *feedback*, log it, and if valid write it to threat memory.

        Returns the updated FeedbackRecord with accepted/rejection_reason set.
        """
        rejection = _validate(feedback)

        if rejection:
            feedback.accepted = False
            feedback.rejection_reason = rejection
            self._log(feedback)
            return feedback

        # Accepted — write to threat memory (for TRUE_POSITIVE and NEW_PATTERN)
        if feedback.feedback_type in (
            FeedbackType.TRUE_POSITIVE,
            FeedbackType.NEW_PATTERN,
        ):
            pattern = ThreatPattern(
                pattern_id=str(uuid.uuid4()),
                pattern_type=feedback.pattern_type,
                indicators=feedback.indicators,
                severity=feedback.severity.upper(),
            )
            self._memory.record(pattern)

        feedback.accepted = True
        feedback.rejection_reason = ""
        self._log(feedback)
        return feedback

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _log(self, record: FeedbackRecord) -> None:
        """Append the feedback record to the feedback log file."""
        import threading
        # We re-use the same approach as ThreatMemory: direct append
        line = record.model_dump_json() + "\n"
        with open(self._log_path, "a", encoding="utf-8") as f:
            f.write(line)
