"""
veil/config.py

Environment-driven configuration for the VEIL runtime.

All modules import from here. Never hardcode credentials or paths elsewhere.

Load order:
  1. .env file (if present, via python-dotenv)
  2. Actual environment variables (override .env)

Usage:
    from veil.config import settings
    client = Groq(api_key=settings.groq_api_key)
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root (parent of this file's directory)
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_env_path, override=False)


class _Settings:
    """
    Runtime configuration. All values sourced from environment variables.
    Fails loudly at import time if a required variable is missing — better
    than failing silently at the first LLM call.
    """

    # ------------------------------------------------------------------
    # Groq — LLM backend for CounterAgent + JudgeAgent
    # ------------------------------------------------------------------

    @property
    def groq_api_key(self) -> str:
        val = os.environ.get("GROQ_API_KEY", "")
        if not val:
            raise EnvironmentError(
                "GROQ_API_KEY is not set. "
                "Copy .env.example to .env and add your Groq API key. "
                "Get one free at https://console.groq.com/keys"
            )
        return val

    @property
    def groq_model_id(self) -> str:
        """Groq model to use. Default: llama3-8b-8192 (fast, free tier)."""
        return os.environ.get("GROQ_MODEL_ID", "llama3-8b-8192")

    # ------------------------------------------------------------------
    # Audit & memory persistence
    # ------------------------------------------------------------------

    @property
    def audit_file_path(self) -> Path:
        return Path(
            os.environ.get("AUDIT_FILE_PATH", "data/audit.jsonl")
        )

    @property
    def threat_memory_path(self) -> Path:
        return Path(
            os.environ.get("THREAT_MEMORY_PATH", "data/threats.jsonl")
        )

    # ------------------------------------------------------------------
    # Pipeline behaviour
    # ------------------------------------------------------------------

    @property
    def risk_threshold_for_agents(self) -> str:
        """
        Minimum RiskLevel that triggers Counter-Agent + Judge invocation.
        Valid values: NONE, LOW, MEDIUM, HIGH, CRITICAL
        """
        return os.environ.get("RISK_THRESHOLD_FOR_AGENTS", "HIGH")

    @property
    def confidence_threshold_for_human_review(self) -> float:
        """
        DecisionResult confidence below this value sets requires_human_review=True.
        """
        return float(
            os.environ.get("CONFIDENCE_THRESHOLD_FOR_HUMAN_REVIEW", "0.6")
        )

    # ------------------------------------------------------------------
    # Gateway API server
    # ------------------------------------------------------------------

    @property
    def gateway_host(self) -> str:
        return os.environ.get("GATEWAY_HOST", "0.0.0.0")

    @property
    def gateway_port(self) -> int:
        return int(os.environ.get("GATEWAY_PORT", "8000"))

    def __repr__(self) -> str:  # never print credentials
        return (
            f"VEILSettings("
            f"model={self.groq_model_id!r}, "
            f"audit={self.audit_file_path}, "
            f"gateway={self.gateway_host}:{self.gateway_port})"
        )


# Singleton — import and use everywhere
settings = _Settings()
