"""
veil/models/action.py

Canonical Action model — the single shared schema that crosses every module
boundary in VEIL. Both Durga's gateway/security layer and Yash's intelligence
layer import from here. Do NOT duplicate this schema elsewhere.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DataClassification(str, Enum):
    """Sensitivity label for a resource or data payload."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    SECRET = "SECRET"
    CREDENTIAL = "CREDENTIAL"
    UNKNOWN = "UNKNOWN"


class Action(BaseModel):
    """
    Normalized representation of a single agent tool-call.

    Every field that is present at normalization time must be populated.
    Fields that are genuinely absent for a given tool type may use their
    default values — do NOT silently drop them.
    """

    # --- Identity ----------------------------------------------------------
    action_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this action instance.",
    )
    agent_id: str = Field(
        description="Identifier of the AI agent that requested this action.",
    )
    session_id: str = Field(
        description="Identifier of the active session. Used for trajectory tracking.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp at which the action was intercepted.",
    )

    # --- Tool call ---------------------------------------------------------
    tool: str = Field(
        description="Logical tool name, e.g. 'database', 'file', 'http', 'shell', 'email'.",
    )
    operation: str = Field(
        description="Operation within the tool, e.g. 'read', 'write', 'execute', 'send'.",
    )
    resource: str = Field(
        description="Target resource identifier, e.g. 'customer_db', '/etc/passwd', 'https://evil.com'.",
    )
    destination: str = Field(
        default="",
        description="Outbound destination for transfer/send operations. Empty string if not applicable.",
    )

    # --- Classification & permissions --------------------------------------
    data_classification: DataClassification = Field(
        default=DataClassification.UNKNOWN,
        description="Sensitivity classification of the resource being accessed. "
                    "Set by the DataClassifier at normalization time.",
    )
    requested_capability: str = Field(
        default="",
        description="Capability token the agent is exercising, e.g. 'database.read'. "
                    "Derived from tool + operation if not explicitly provided.",
    )

    # --- Intent & provenance -----------------------------------------------
    purpose: str = Field(
        default="",
        description="Agent-declared reason for this action. Treated as untrusted input "
                    "and inspected for injection signals.",
    )
    provenance: str = Field(
        default="",
        description="Source that triggered this action: 'user_instruction', "
                    "'agent_plan', 'tool_output', 'external_content'.",
    )

    # --- Extensibility -----------------------------------------------------
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary key-value context supplied by the agent framework. "
                    "Treated as untrusted.",
    )

    model_config = {"frozen": True}
