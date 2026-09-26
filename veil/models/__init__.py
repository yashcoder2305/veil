"""
veil/models/__init__.py

Public surface of the VEIL shared models package.

Import everything from here — do NOT import directly from the sub-modules.
This gives us freedom to reorganise internals without breaking consumers.

Usage:
    from veil.models import Action, Decision, DecisionResult, RiskLevel, ...
"""

from veil.models.action import Action, DataClassification
from veil.models.decisions import Decision, DecisionResult
from veil.models.results import (
    CapabilityResult,
    InjectionResult,
    PolicyResult,
    RiskLevel,
    RiskResult,
)

__all__ = [
    # action
    "Action",
    "DataClassification",
    # decisions
    "Decision",
    "DecisionResult",
    # results
    "CapabilityResult",
    "InjectionResult",
    "PolicyResult",
    "RiskLevel",
    "RiskResult",
]
