"""
veil/agents/revocation.py

RevocationEngine — tracks and enforces capability revocations per session.

When DecisionEngine returns REVOKE, the pipeline calls RevocationEngine.revoke().
On every subsequent call, CapabilityManager queries RevocationEngine.is_revoked()
before granting any capability.

State is in-memory for simplicity. In production this would be backed by a
Redis or persistent store to survive restarts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# RevocationRecord — stored for each revocation event
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RevocationRecord:
    """Immutable record of a single capability revocation."""

    agent_id: str
    session_id: str
    capability: str
    reason: str
    revoked_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# RevocationEngine
# ---------------------------------------------------------------------------


class RevocationEngine:
    """
    Maintains a per-(session, agent, capability) revocation store.

    Thread-safety: single-threaded use assumed; wrap with a lock for
    concurrent access.
    """

    def __init__(self) -> None:
        # key: (session_id, agent_id, capability) → RevocationRecord
        self._revocations: dict[tuple[str, str, str], RevocationRecord] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def revoke(
        self,
        agent_id: str,
        session_id: str,
        capability: str,
        reason: str = "Revoked by VEIL enforcement engine.",
    ) -> RevocationRecord:
        """
        Revoke *capability* for (*agent_id*, *session_id*).

        Idempotent — revoking an already-revoked capability is a no-op that
        returns the existing record.
        """
        key = (session_id, agent_id, capability)
        if key not in self._revocations:
            record = RevocationRecord(
                agent_id=agent_id,
                session_id=session_id,
                capability=capability,
                reason=reason,
            )
            self._revocations[key] = record
        return self._revocations[key]

    def is_revoked(
        self,
        agent_id: str,
        session_id: str,
        capability: str,
    ) -> bool:
        """Return True if *capability* is currently revoked for this session."""
        return (session_id, agent_id, capability) in self._revocations

    def get_record(
        self,
        agent_id: str,
        session_id: str,
        capability: str,
    ) -> RevocationRecord | None:
        """Return the RevocationRecord or None if not revoked."""
        return self._revocations.get((session_id, agent_id, capability))

    def list_revocations(
        self,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> list[RevocationRecord]:
        """
        List all revocation records, optionally filtered by session and/or agent.
        """
        records = list(self._revocations.values())
        if session_id is not None:
            records = [r for r in records if r.session_id == session_id]
        if agent_id is not None:
            records = [r for r in records if r.agent_id == agent_id]
        return records

    def clear_session(self, session_id: str) -> int:
        """
        Remove all revocations for a session (e.g. on session teardown).
        Returns the number of records removed.
        """
        keys_to_remove = [k for k in self._revocations if k[0] == session_id]
        for k in keys_to_remove:
            del self._revocations[k]
        return len(keys_to_remove)
