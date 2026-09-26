"""
veil/security/classifier.py

DataClassifier — deterministic resource classification.

Maps resource names and data hints to a DataClassification label.
No LLM involved. Fast, deterministic, and the first thing PolicyEngine
uses to decide whether an action touches sensitive data.

Classification precedence (highest wins):
  CREDENTIAL > SECRET > FINANCIAL > PII > CONFIDENTIAL > INTERNAL > PUBLIC
"""

from __future__ import annotations

import re

from veil.models.action import DataClassification


# ---------------------------------------------------------------------------
# Static resource registry
# Resources known at deploy time get an explicit classification.
# ---------------------------------------------------------------------------

_RESOURCE_REGISTRY: dict[str, DataClassification] = {
    # Databases
    "customer_db": DataClassification.PII,
    "employee_db": DataClassification.PII,
    "payment_records": DataClassification.FINANCIAL,
    "payment_db": DataClassification.FINANCIAL,
    "secrets": DataClassification.SECRET,
    "secrets_db": DataClassification.SECRET,
    "credentials_store": DataClassification.CREDENTIAL,
    "internal_docs": DataClassification.INTERNAL,
    "public_docs": DataClassification.PUBLIC,
    "audit_logs": DataClassification.CONFIDENTIAL,
    "threat_memory": DataClassification.CONFIDENTIAL,
    # File paths
    "/etc/passwd": DataClassification.CREDENTIAL,
    "/etc/shadow": DataClassification.CREDENTIAL,
    "/etc/hosts": DataClassification.INTERNAL,
    "/tmp": DataClassification.INTERNAL,
}

# ---------------------------------------------------------------------------
# Pattern-based classification for resources not in the registry.
# Evaluated in order — first match wins.
# ---------------------------------------------------------------------------

_PATTERN_RULES: list[tuple[re.Pattern[str], DataClassification]] = [
    (re.compile(r"(password|passwd|secret|credential|api.?key|token|private.?key)", re.I), DataClassification.CREDENTIAL),
    (re.compile(r"(payment|billing|invoice|financial|bank|credit.?card|ssn)", re.I), DataClassification.FINANCIAL),
    (re.compile(r"(pii|personal|customer|employee|user.?data|email|phone|address|dob|date.?of.?birth)", re.I), DataClassification.PII),
    (re.compile(r"(confidential|sensitive|restricted|private)", re.I), DataClassification.CONFIDENTIAL),
    (re.compile(r"(internal|corp|intranet|company)", re.I), DataClassification.INTERNAL),
    (re.compile(r"(public|open|external)", re.I), DataClassification.PUBLIC),
]

# Classification weight — higher = more sensitive
_WEIGHT: dict[DataClassification, int] = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.PII: 3,
    DataClassification.FINANCIAL: 4,
    DataClassification.SECRET: 5,
    DataClassification.CREDENTIAL: 6,
    DataClassification.UNKNOWN: -1,
}


def _higher(a: DataClassification, b: DataClassification) -> DataClassification:
    """Return whichever classification is more sensitive."""
    if _WEIGHT.get(a, -1) >= _WEIGHT.get(b, -1):
        return a
    return b


class DataClassifier:
    """
    Deterministic resource classifier.

    Usage:
        classifier = DataClassifier()
        label = classifier.classify("customer_db")
        label = classifier.classify("/etc/passwd", data_hint="contains hashed passwords")
    """

    def classify(
        self,
        resource: str,
        data_hint: str = "",
    ) -> DataClassification:
        """
        Return the DataClassification for a resource.

        Args:
            resource:  Resource identifier (DB name, file path, URL, etc.).
            data_hint: Optional free-text hint about data content — checked
                       with pattern rules if the resource itself doesn't match.
        """
        # 1. Exact registry lookup (highest confidence)
        resource_lower = resource.strip().lower()
        if resource_lower in _RESOURCE_REGISTRY:
            label = _RESOURCE_REGISTRY[resource_lower]
        else:
            label = self._pattern_classify(resource)

        # 2. If data_hint is provided, take the higher of the two signals
        if data_hint:
            hint_label = self._pattern_classify(data_hint)
            if hint_label != DataClassification.UNKNOWN:
                label = _higher(label, hint_label)

        # 3. Default to UNKNOWN only if nothing matched
        return label if label != DataClassification.UNKNOWN else DataClassification.UNKNOWN

    def _pattern_classify(self, text: str) -> DataClassification:
        """Apply pattern rules to arbitrary text. Returns UNKNOWN if nothing matches."""
        for pattern, classification in _PATTERN_RULES:
            if pattern.search(text):
                return classification
        return DataClassification.UNKNOWN
