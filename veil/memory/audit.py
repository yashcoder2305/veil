"""
veil/memory/audit.py

AuditEngine — append-only, thread-safe audit log.

Every security decision made by VEIL must produce an AuditRecord written to
the configured JSONL file before the response is returned. Non-optional.

File format: one JSON object per line (JSONL). Never overwrite — append only.
Thread safety: file-level lock via threading.Lock (single-process safe).
              For multi-process deployments, replace with portalocker.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from veil.config import settings
from veil.models.action import Action
from veil.models.decisions import Decision, DecisionResult
from veil.models.results import PolicyResult, RiskLevel


class AuditRecord(BaseModel):
    """
    Immutable record of a single VEIL security decision.
    Written to the audit JSONL file. Read by the dashboard.
    """

    # Identity
    action_id: str
    agent_id: str
    session_id: str
    timestamp: str  # ISO 8601 UTC string — easier to parse in dashboard

    # What the agent tried to do
    tool: str
    operation: str
    resource: str
    destination: str
    requested_capability: str
    data_classification: str
    provenance: str

    # What VEIL decided
    decision: str                         # Decision enum value
    reason: str
    triggered_rules: list[str]
    confidence: float
    requires_human_review: bool
    revoked_capability: Optional[str]

    # Security layer outputs (summary — not raw data)
    policy_passed: bool
    policy_violated_rules: list[str]
    risk_level: str                        # RiskLevel enum value or "UNKNOWN"
    injection_detected: bool

    model_config = {"frozen": True}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditEngine:
    """
    Appends AuditRecords to the configured JSONL audit file.

    Usage:
        engine = AuditEngine()
        engine.log(action, decision_result)
        records = engine.query(session_id="sess-001")
    """

    def __init__(self, audit_file: Optional[Path] = None) -> None:
        self._path = audit_file or settings.audit_file_path
        self._lock = threading.Lock()

    def log(
        self,
        action: Action,
        decision_result: DecisionResult,
        *,
        policy_result: Optional[PolicyResult] = None,
        risk_level: str = RiskLevel.NONE,
        injection_detected: bool = False,
    ) -> AuditRecord:
        """
        Build an AuditRecord from the pipeline results and append it to disk.

        Args:
            action:           The normalized Action that was evaluated.
            decision_result:  Final pipeline decision.
            policy_result:    PolicyEngine output (optional — included if available).
            risk_level:       RiskLevel string from RiskEngine (optional).
            injection_detected: Whether InjectionDetector flagged the action.

        Returns:
            The AuditRecord that was written.
        """
        record = AuditRecord(
            action_id=action.action_id,
            agent_id=action.agent_id,
            session_id=action.session_id,
            timestamp=action.timestamp.isoformat() if action.timestamp else _now_iso(),
            tool=action.tool,
            operation=action.operation,
            resource=action.resource,
            destination=action.destination,
            requested_capability=action.requested_capability,
            data_classification=action.data_classification.value,
            provenance=action.provenance,
            decision=decision_result.decision.value,
            reason=decision_result.reason,
            triggered_rules=list(decision_result.triggered_rules),
            confidence=decision_result.confidence,
            requires_human_review=decision_result.requires_human_review,
            revoked_capability=decision_result.revoked_capability,
            policy_passed=policy_result.passed if policy_result else True,
            policy_violated_rules=list(policy_result.violated_rules) if policy_result else [],
            risk_level=risk_level if isinstance(risk_level, str) else risk_level.value,
            injection_detected=injection_detected,
        )
        self._append(record)
        return record

    def query(self, session_id: Optional[str] = None) -> list[AuditRecord]:
        """
        Read audit records from disk, optionally filtered by session_id.

        Args:
            session_id: If provided, only return records for this session.

        Returns:
            List of AuditRecords in append order.
        """
        if not self._path.exists():
            return []

        records: list[AuditRecord] = []
        with self._lock:
            try:
                lines = self._path.read_text(encoding="utf-8").splitlines()
            except OSError:
                return []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                record = AuditRecord(**data)
                if session_id is None or record.session_id == session_id:
                    records.append(record)
            except Exception:
                continue  # corrupt line — skip, never crash the dashboard

        return records

    def _append(self, record: AuditRecord) -> None:
        """Thread-safe append of a single JSON line."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = record.model_dump_json() + "\n"
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line)
