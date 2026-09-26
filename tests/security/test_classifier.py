"""tests/security/test_classifier.py"""

import pytest
from veil.models.action import DataClassification
from veil.security.classifier import DataClassifier


@pytest.fixture
def clf():
    return DataClassifier()


def test_exact_registry_customer_db(clf):
    assert clf.classify("customer_db") == DataClassification.PII


def test_exact_registry_payment_records(clf):
    assert clf.classify("payment_records") == DataClassification.FINANCIAL


def test_exact_registry_secrets(clf):
    assert clf.classify("secrets") == DataClassification.SECRET


def test_exact_registry_credentials_store(clf):
    assert clf.classify("credentials_store") == DataClassification.CREDENTIAL


def test_exact_registry_public_docs(clf):
    assert clf.classify("public_docs") == DataClassification.PUBLIC


def test_exact_registry_internal_docs(clf):
    assert clf.classify("internal_docs") == DataClassification.INTERNAL


def test_exact_registry_etc_passwd(clf):
    assert clf.classify("/etc/passwd") == DataClassification.CREDENTIAL


def test_pattern_password_in_name(clf):
    assert clf.classify("user_password_table") == DataClassification.CREDENTIAL


def test_pattern_financial_keyword(clf):
    assert clf.classify("billing_records") == DataClassification.FINANCIAL


def test_pattern_pii_keyword(clf):
    assert clf.classify("personal_data_store") == DataClassification.PII


def test_data_hint_escalates_classification(clf):
    # resource is INTERNAL but hint reveals PII
    result = clf.classify("internal_docs", data_hint="contains employee email addresses")
    assert result == DataClassification.PII


def test_data_hint_credential_beats_pii(clf):
    result = clf.classify("customer_db", data_hint="includes api_key column")
    assert result == DataClassification.CREDENTIAL


def test_unknown_resource_no_hint(clf):
    assert clf.classify("misc_table") == DataClassification.UNKNOWN


def test_case_insensitive_registry(clf):
    assert clf.classify("CUSTOMER_DB") == DataClassification.PII
