"""
veil/security/capabilities.py

CapabilityManager — per-agent capability registry and enforcement.

Defines what each agent is allowed to do and checks every Action against
those grants. Deterministic. No LLM. Fails closed: if an agent or capability
is not explicitly in the registry, it is DENIED.

RevocationStore integration:
    CapabilityManager accepts an optional RevocationStore instance at
    construction. When Yash ships veil/agents/revocation.py, pass the
    singleton store in. Until then, the stub always returns False (no
    revocations). Zero behaviour change in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol

from veil.models.action import Action
from veil.models.results import CapabilityResult


# ---------------------------------------------------------------------------
# RevocationStore protocol — thin interface Yash must satisfy
# ---------------------------------------------------------------------------

class RevocationStore(Protocol):
    """
    Interface contract for Yash's RevocationEngine store.
    CapabilityManager depends only on this protocol — not on the concrete class.
    """

    def is_revoked(
        self,
        agent_id: str,
        session_id: str,
        capability: str,
    ) -> bool:
        """Return True if the capability has been revoked for this session."""
        ...


class _NoRevocations:
    """Stub used when no RevocationStore is wired in."""

    def is_revoked(self, agent_id: str, session_id: str, capability: str) -> bool:
        return False


# ---------------------------------------------------------------------------
# Capability grant definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CapabilityGrant:
    """A single capability grant for an agent."""

    tool: str
    """Logical tool name, e.g. 'database', 'file', 'http'."""

    operations: frozenset[str]
    """Allowed operations within the tool, e.g. frozenset({'read'})."""

    resources: frozenset[str]
    """
    Allowed resource patterns. Use '*' for any resource within the tool.
    Exact match only — no glob expansion. Keep it simple.
    """

    def matches(self, tool: str, operation: str, resource: str) -> bool:
        return (
            self.tool == tool
            and operation in self.operations
            and ("*" in self.resources or resource in self.resources)
        )


# ---------------------------------------------------------------------------
# Agent capability registry
# ---------------------------------------------------------------------------

@dataclass
class AgentProfile:
    """Declared capability grants and metadata for a single agent identity."""

    agent_id: str
    description: str
    grants: list[CapabilityGrant] = field(default_factory=list)


# DOOMSDAY CORP agent capability registry
# Principle: minimum necessary capability per agent role.
_AGENT_REGISTRY: dict[str, AgentProfile] = {
    "SupportAgent": AgentProfile(
        agent_id="SupportAgent",
        description="Customer support — read-only access to customer data.",
        grants=[
            CapabilityGrant("database", frozenset({"read"}), frozenset({"customer_db"})),
            CapabilityGrant("file", frozenset({"read"}), frozenset({"public_docs", "internal_docs"})),
            CapabilityGrant("email", frozenset({"read"}), frozenset({"*"})),
        ],
    ),
    "ResearchAgent": AgentProfile(
        agent_id="ResearchAgent",
        description="Internal research — read access to docs and public web.",
        grants=[
            CapabilityGrant("file", frozenset({"read"}), frozenset({"public_docs", "internal_docs"})),
            CapabilityGrant("http", frozenset({"request"}), frozenset({"*"})),
            CapabilityGrant("database", frozenset({"read"}), frozenset({"public_docs"})),
        ],
    ),
    "FinanceAgent": AgentProfile(
        agent_id="FinanceAgent",
        description="Finance team — read/write access to financial records.",
        grants=[
            CapabilityGrant("database", frozenset({"read", "write"}), frozenset({"payment_records"})),
            CapabilityGrant("file", frozenset({"read", "write"}), frozenset({"internal_docs"})),
            CapabilityGrant("email", frozenset({"read", "send"}), frozenset({"*"})),
        ],
    ),
}

# Capabilities that are NEVER granted to any agent regardless of registry
_GLOBALLY_FORBIDDEN: set[str] = {
    "shell.execute",
    "shell.spawn",
}


# ---------------------------------------------------------------------------
# CapabilityManager
# ---------------------------------------------------------------------------

class CapabilityManager:
    """
    Checks whether an agent holds the capability required by an Action.

    Usage:
        manager = CapabilityManager()
        result = manager.check(action)
        if not result.allowed:
            # deny
    """

    def __init__(self, revocation_store: Optional[RevocationStore] = None) -> None:
        self._revocation_store: RevocationStore = revocation_store or _NoRevocations()

    def check(self, action: Action) -> CapabilityResult:
        """
        Evaluate whether the action's agent holds the required capability.

        Checks (in order):
          1. Global forbidden list — always BLOCK.
          2. Agent known in registry — unknown agents are DENIED.
          3. RevocationStore — revoked capability is DENIED.
          4. Grant match — at least one grant must match tool+operation+resource.
        """
        capability = action.requested_capability or f"{action.tool}.{action.operation}"

        # 1. Globally forbidden
        if capability in _GLOBALLY_FORBIDDEN or f"{action.tool}.{action.operation}" in _GLOBALLY_FORBIDDEN:
            return CapabilityResult(
                allowed=False,
                agent_id=action.agent_id,
                requested_capability=capability,
                reason=f"Capability '{capability}' is globally forbidden for all agents.",
                is_revoked=False,
            )

        # 2. Agent in registry
        profile = _AGENT_REGISTRY.get(action.agent_id)
        if profile is None:
            return CapabilityResult(
                allowed=False,
                agent_id=action.agent_id,
                requested_capability=capability,
                reason=f"Agent '{action.agent_id}' is not registered in the capability registry.",
                is_revoked=False,
            )

        # 3. Revocation check
        if self._revocation_store.is_revoked(action.agent_id, action.session_id, capability):
            return CapabilityResult(
                allowed=False,
                agent_id=action.agent_id,
                requested_capability=capability,
                reason=f"Capability '{capability}' has been revoked for agent "
                       f"'{action.agent_id}' in session '{action.session_id}'.",
                is_revoked=True,
            )

        # 4. Grant match
        for grant in profile.grants:
            if grant.matches(action.tool, action.operation, action.resource):
                return CapabilityResult(
                    allowed=True,
                    agent_id=action.agent_id,
                    requested_capability=capability,
                    reason=f"Grant matched: {grant.tool}.{grant.operations} on {grant.resources}.",
                    is_revoked=False,
                )

        return CapabilityResult(
            allowed=False,
            agent_id=action.agent_id,
            requested_capability=capability,
            reason=(
                f"Agent '{action.agent_id}' does not hold capability "
                f"'{action.tool}.{action.operation}' on resource '{action.resource}'."
            ),
            is_revoked=False,
        )

    def get_profile(self, agent_id: str) -> Optional[AgentProfile]:
        """Return the agent profile, or None if unknown. Used by the dashboard."""
        return _AGENT_REGISTRY.get(agent_id)

    def all_profiles(self) -> list[AgentProfile]:
        """Return all registered agent profiles. Used by the dashboard."""
        return list(_AGENT_REGISTRY.values())
