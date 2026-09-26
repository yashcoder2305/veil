"""
veil/gateway/normalizer.py

ActionNormalizer — converts raw tool-call dicts into canonical Action objects.

Accepts the loosely-structured payload that any agent framework might send and
maps it to the strict Action model. The classifier runs here so that every
Action entering the pipeline already carries a data_classification.

Field mapping strategy:
  - Accept both camelCase and snake_case keys (agent frameworks vary).
  - Never silently drop required fields — raise ValueError with a clear message.
  - For genuinely optional fields, use Action defaults.
"""

from __future__ import annotations

from typing import Any

from veil.models.action import Action, DataClassification
from veil.security.classifier import DataClassifier

_classifier = DataClassifier()

# Accepted key aliases → canonical Action field name
_FIELD_ALIASES: dict[str, str] = {
    # agent identity
    "agentId": "agent_id",
    "agent": "agent_id",
    "sessionId": "session_id",
    "session": "session_id",
    # tool call
    "toolName": "tool",
    "tool_name": "tool",
    "op": "operation",
    "action": "operation",
    # resource
    "target": "resource",
    "path": "resource",
    "url": "resource",
    # destination
    "dest": "destination",
    "endpoint": "destination",
    "to": "destination",
    # intent / provenance
    "intent": "purpose",
    "reason": "purpose",
    "source": "provenance",
    "triggered_by": "provenance",
    # capability
    "capability": "requested_capability",
    "cap": "requested_capability",
}

_REQUIRED_FIELDS: frozenset[str] = frozenset({
    "agent_id",
    "session_id",
    "tool",
    "operation",
    "resource",
})


class NormalizationError(ValueError):
    """Raised when a raw payload cannot be normalized into a valid Action."""
    pass


class ActionNormalizer:
    """
    Converts a raw tool-call dict into a fully-typed Action.

    Usage:
        normalizer = ActionNormalizer()
        action = normalizer.normalize(raw_payload)
    """

    def normalize(self, raw: dict[str, Any]) -> Action:
        """
        Map raw dict keys to Action fields and instantiate.

        Args:
            raw: Arbitrary dict from an agent framework tool-call.

        Returns:
            Fully constructed Action with data_classification populated.

        Raises:
            NormalizationError: If required fields are missing after alias resolution.
        """
        if not isinstance(raw, dict):
            raise NormalizationError(f"Expected dict payload, got {type(raw).__name__}.")

        normalized: dict[str, Any] = {}

        for key, value in raw.items():
            canonical = _FIELD_ALIASES.get(key, key)
            normalized[canonical] = value

        # Check required fields
        missing = _REQUIRED_FIELDS - normalized.keys()
        if missing:
            raise NormalizationError(
                f"Raw payload is missing required fields: {sorted(missing)}. "
                f"Received keys: {sorted(raw.keys())}."
            )

        # Resolve requested_capability from tool+operation if not supplied
        if not normalized.get("requested_capability"):
            normalized["requested_capability"] = (
                f"{normalized['tool']}.{normalized['operation']}"
            )

        # Classify the resource — overrides any caller-supplied value so the
        # classifier is the single source of truth for data_classification.
        resource = normalized["resource"]
        data_hint = str(normalized.get("metadata", {}).get("data_hint", ""))
        normalized["data_classification"] = _classifier.classify(resource, data_hint)

        # Strip unknown fields — Pydantic will error on extras by default
        known_fields = set(Action.model_fields.keys())
        filtered = {k: v for k, v in normalized.items() if k in known_fields}

        try:
            return Action(**filtered)
        except Exception as exc:
            raise NormalizationError(f"Failed to construct Action: {exc}") from exc
