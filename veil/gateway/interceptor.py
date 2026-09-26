"""
veil/gateway/interceptor.py

ActionInterceptor — entry point for all agent tool-calls into VEIL.

Responsibilities:
  1. Validate the raw payload structure (must be a non-empty dict).
  2. Call the normalizer to produce a typed Action.
  3. Return the Action to the pipeline — no security logic here.

The interceptor does NOT make security decisions. It only gates malformed
payloads before they waste downstream processing.
"""

from __future__ import annotations

from typing import Any

from veil.gateway.normalizer import ActionNormalizer, NormalizationError
from veil.models.action import Action


class InterceptionError(ValueError):
    """Raised when a payload is structurally invalid and cannot be intercepted."""
    pass


class ActionInterceptor:
    """
    Receives raw tool-call payloads and returns a normalized Action.

    Usage:
        interceptor = ActionInterceptor()
        action = interceptor.intercept(raw_payload)
    """

    def __init__(self) -> None:
        self._normalizer = ActionNormalizer()

    def intercept(self, raw_payload: Any) -> Action:
        """
        Validate and normalize a raw tool-call payload.

        Args:
            raw_payload: Any object received from the agent framework.

        Returns:
            Normalized Action ready for the security pipeline.

        Raises:
            InterceptionError: If the payload is structurally invalid.
            NormalizationError: If required fields are missing after normalization.
        """
        if raw_payload is None:
            raise InterceptionError("Received null payload — nothing to intercept.")

        if not isinstance(raw_payload, dict):
            raise InterceptionError(
                f"Payload must be a dict, got {type(raw_payload).__name__}. "
                f"Ensure the agent framework is serializing tool calls correctly."
            )

        if not raw_payload:
            raise InterceptionError("Received empty payload dict.")

        try:
            return self._normalizer.normalize(raw_payload)
        except NormalizationError:
            raise  # let pipeline handle normalization errors directly
        except Exception as exc:
            raise InterceptionError(f"Unexpected error during interception: {exc}") from exc
