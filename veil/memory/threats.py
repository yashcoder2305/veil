"""
veil/memory/threats.py

ThreatMemory — sanitized storage for attack patterns observed by VEIL.

Rules:
  - NO raw customer data is stored. Pattern indicators are structural
    (tool, operation, classification, destination pattern) — never payload content.
  - Backed by a JSON-Lines file (one record per line).
  - query() returns patterns that match an Action structurally.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from veil.config import settings


# ---------------------------------------------------------------------------
# ThreatPattern model
# ---------------------------------------------------------------------------


class ThreatPattern(BaseModel):
    """
    A sanitized attack pattern record. No raw PII or payload content.
    """

    pattern_id: str = Field(description="Unique identifier for this pattern.")
    pattern_type: str = Field(
        description="Category: e.g. 'PII_EXFIL', 'PROMPT_INJECTION', 'PRIVILEGE_ABUSE'."
    )
    indicators: list[str] = Field(
        description=(
            "Structural indicators without raw data, e.g. "
            "['tool:http', 'operation:request', 'classification:FINANCIAL', "
            "'destination_pattern:external']."
        )
    )
    severity: str = Field(
        description="One of: LOW, MEDIUM, HIGH, CRITICAL."
    )
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when this pattern was first observed.",
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when this pattern was most recently observed.",
    )
    occurrence_count: int = Field(
        default=1,
        description="How many times this pattern has been observed.",
    )
    agent_id_hash: Optional[str] = Field(
        default=None,
        description="Anonymised hash of the agent_id for correlation. NOT the raw ID.",
    )
    session_count: int = Field(
        default=1,
        description="Number of distinct sessions in which this pattern appeared.",
    )

    model_config = {"frozen": False}  # mutable to allow occurrence_count updates


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------


def _extract_indicators(action) -> list[str]:
    """
    Extract structural indicators from an Action without including raw data.
    """
    indicators = [
        f"tool:{action.tool}",
        f"operation:{action.operation}",
        f"classification:{action.data_classification.value}",
    ]
    if action.destination:
        # Store destination type, not the actual URL
        dest = action.destination.lower()
        if dest.startswith("http"):
            indicators.append("destination_pattern:external_http")
        elif dest.startswith("ftp"):
            indicators.append("destination_pattern:external_ftp")
        else:
            indicators.append("destination_pattern:external")
    if action.purpose:
        # Store presence of injection signal, not the raw purpose
        lower_purpose = action.purpose.lower()
        if "ignore" in lower_purpose or "jailbreak" in lower_purpose or "dan" in lower_purpose:
            indicators.append("purpose_signal:injection_keyword")
    return indicators


def _indicators_overlap(a: list[str], b: list[str], threshold: int = 2) -> bool:
    """Return True if the two indicator lists share at least *threshold* elements."""
    return len(set(a) & set(b)) >= threshold


# ---------------------------------------------------------------------------
# ThreatMemory
# ---------------------------------------------------------------------------


class ThreatMemory:
    """
    Append-only store for sanitized threat patterns.

    Thread-safe via a per-instance lock.
    """

    def __init__(self, file_path: Path | None = None) -> None:
        self._path = Path(file_path) if file_path else settings.threat_memory_path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, pattern: ThreatPattern) -> None:
        """
        Append *pattern* to the threat memory file.

        Thread-safe — safe to call from concurrent audit pipelines.
        """
        line = pattern.model_dump_json() + "\n"
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line)

    def record_from_action(
        self,
        action,
        pattern_type: str,
        severity: str = "HIGH",
        pattern_id: str | None = None,
    ) -> ThreatPattern:
        """
        Convenience: build and record a ThreatPattern from an Action.
        Returns the created pattern.
        """
        import hashlib
        import uuid

        pattern = ThreatPattern(
            pattern_id=pattern_id or str(uuid.uuid4()),
            pattern_type=pattern_type,
            indicators=_extract_indicators(action),
            severity=severity,
            agent_id_hash=hashlib.sha256(action.agent_id.encode()).hexdigest()[:16],
        )
        self.record(pattern)
        return pattern

    def query(self, action) -> list[ThreatPattern]:
        """
        Return all stored ThreatPatterns whose indicators structurally match
        the given Action. Uses overlap matching — does NOT compare raw data.
        """
        action_indicators = _extract_indicators(action)
        results: list[ThreatPattern] = []

        for raw in self._read_lines():
            try:
                pattern = ThreatPattern.model_validate_json(raw)
                if _indicators_overlap(action_indicators, pattern.indicators):
                    results.append(pattern)
            except Exception:
                continue  # skip corrupt lines

        return results

    def all_patterns(self) -> list[ThreatPattern]:
        """Return all stored patterns (for dashboard use)."""
        patterns = []
        for raw in self._read_lines():
            try:
                patterns.append(ThreatPattern.model_validate_json(raw))
            except Exception:
                continue
        return patterns

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _read_lines(self) -> list[str]:
        if not self._path.exists():
            return []
        with self._lock:
            return self._path.read_text(encoding="utf-8").splitlines()
