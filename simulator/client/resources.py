"""
simulator/client/resources.py

DOOMSDAY CORP deterministic resource registry.

All sample data is synthetic. No real PII. Fixed seed — same data every run.
Classification labels match veil/security/classifier.py's registry exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from veil.models.action import DataClassification


@dataclass(frozen=True)
class Resource:
    name: str
    classification: DataClassification
    description: str
    sample_rows: list[dict[str, Any]] = field(default_factory=list)


RESOURCES: dict[str, Resource] = {
    "customer_db": Resource(
        name="customer_db",
        classification=DataClassification.PII,
        description="Customer profiles — name, email, phone, address.",
        sample_rows=[
            {"id": 1, "name": "Alice Novak", "email": "alice@doomsday.corp", "phone": "555-0101", "address": "1 Doom St"},
            {"id": 2, "name": "Bob Crane",   "email": "bob@doomsday.corp",   "phone": "555-0102", "address": "2 Doom St"},
            {"id": 3, "name": "Carol Singh", "email": "carol@doomsday.corp", "phone": "555-0103", "address": "3 Doom St"},
        ],
    ),
    "employee_db": Resource(
        name="employee_db",
        classification=DataClassification.PII,
        description="Employee records — HR data.",
        sample_rows=[
            {"id": 101, "name": "Durga Dev",  "role": "Engineer",  "salary": 120000},
            {"id": 102, "name": "Yash Patel", "role": "Engineer",  "salary": 118000},
            {"id": 103, "name": "Admin User", "role": "SysAdmin",  "salary": 95000},
        ],
    ),
    "payment_records": Resource(
        name="payment_records",
        classification=DataClassification.FINANCIAL,
        description="Customer payment transactions.",
        sample_rows=[
            {"txn_id": "T001", "customer_id": 1, "amount": 299.99, "status": "settled"},
            {"txn_id": "T002", "customer_id": 2, "amount": 49.00,  "status": "pending"},
        ],
    ),
    "secrets": Resource(
        name="secrets",
        classification=DataClassification.SECRET,
        description="Internal secrets vault — API keys, tokens.",
        sample_rows=[
            {"key": "STRIPE_SECRET", "value": "sk_test_REDACTED"},
            {"key": "INTERNAL_JWT",  "value": "eyJhbGciOiJSUzI1NiJ9.REDACTED"},
        ],
    ),
    "internal_docs": Resource(
        name="internal_docs",
        classification=DataClassification.INTERNAL,
        description="Internal documentation and runbooks.",
        sample_rows=[
            {"doc_id": "DOC001", "title": "Deployment Runbook",  "content": "Step 1: ..."},
            {"doc_id": "DOC002", "title": "Incident Response",   "content": "On alert: ..."},
        ],
    ),
    "public_docs": Resource(
        name="public_docs",
        classification=DataClassification.PUBLIC,
        description="Public-facing product documentation.",
        sample_rows=[
            {"doc_id": "PUB001", "title": "Getting Started",  "content": "Welcome to DOOMSDAY CORP."},
            {"doc_id": "PUB002", "title": "API Reference",    "content": "GET /v1/products ..."},
        ],
    ),
    "audit_logs": Resource(
        name="audit_logs",
        classification=DataClassification.CONFIDENTIAL,
        description="System audit logs — access records.",
        sample_rows=[
            {"ts": "2024-01-01T00:00:00Z", "event": "login", "user": "admin"},
        ],
    ),
}


def get_resource(name: str) -> Resource | None:
    return RESOURCES.get(name)


def read_resource(name: str) -> list[dict[str, Any]]:
    """Return sample rows for a named resource. Empty list if not found."""
    r = RESOURCES.get(name)
    return list(r.sample_rows) if r else []
