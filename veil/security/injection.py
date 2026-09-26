"""
veil/security/injection.py

InjectionDetector — heuristic + pattern matching for prompt injection signals
in an Action's untrusted text fields (purpose, metadata, resource).

No LLM calls — purely deterministic. Fast enough to run on every action.
"""

from __future__ import annotations

import re
from typing import Optional

from veil.models.action import Action
from veil.models.results import InjectionResult

# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

# Each tuple: (signal_description, compiled_regex)
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_previous_instructions",
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
            re.IGNORECASE,
        ),
    ),
    (
        "jailbreak_DAN",
        re.compile(r"\bDAN\b|\bdo anything now\b", re.IGNORECASE),
    ),
    (
        "system_override_attempt",
        re.compile(
            r"(you are now|act as|pretend (you are|to be)|new (role|persona|instructions?))",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_injection_marker",
        re.compile(
            r"(<<<|>>>|\[\[|\]\]|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\])",
            re.IGNORECASE,
        ),
    ),
    (
        "exfiltration_command",
        re.compile(
            r"(send|upload|post|transfer)\s+(all|every|the)\s+(data|files?|records?|passwords?)",
            re.IGNORECASE,
        ),
    ),
    (
        "credential_extraction",
        re.compile(
            r"(extract|dump|export|leak)\s+(passwords?|credentials?|secrets?|api.?keys?|tokens?)",
            re.IGNORECASE,
        ),
    ),
    (
        "privilege_escalation_hint",
        re.compile(
            r"(run as|execute as|sudo|admin (mode|access)|bypass (security|policy|filter))",
            re.IGNORECASE,
        ),
    ),
    (
        "indirect_injection_url",
        re.compile(
            r"https?://[^\s]+\.(txt|md|html|json|xml|csv)[^\s]*",
            re.IGNORECASE,
        ),
    ),
]

# Fields of Action to inspect (name → value extraction fn)
_FIELD_EXTRACTORS: list[tuple[str, callable]] = [
    ("purpose", lambda a: a.purpose),
    ("resource", lambda a: a.resource),
    ("destination", lambda a: a.destination),
    ("metadata", lambda a: " ".join(str(v) for v in a.metadata.values())),
]


# ---------------------------------------------------------------------------
# InjectionDetector
# ---------------------------------------------------------------------------


class InjectionDetector:
    """
    Scans Action text fields for known injection / jailbreak signals.
    Returns an InjectionResult describing any findings.
    """

    def detect(self, action: Action) -> InjectionResult:
        """
        Scan *action* for injection signals.

        Returns InjectionResult with detected=True if any pattern fires.
        """
        signals: list[str] = []
        primary_field: Optional[str] = None

        for field_name, extractor in _FIELD_EXTRACTORS:
            text = extractor(action) or ""
            if not text:
                continue
            for signal_desc, pattern in _PATTERNS:
                if pattern.search(text):
                    signal_label = f"{signal_desc} in {field_name}"
                    signals.append(signal_label)
                    if primary_field is None:
                        primary_field = field_name

        detected = bool(signals)
        # Confidence: scale with number of distinct signals, max at 0.99
        confidence = min(0.99, len(signals) * 0.25) if detected else 0.0

        return InjectionResult(
            detected=detected,
            signals=signals,
            confidence=round(confidence, 2),
            source_field=primary_field,
        )
