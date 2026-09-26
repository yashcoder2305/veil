"""
tests/memory/test_threats.py
"""
from __future__ import annotations

import pytest
import tempfile
from pathlib import Path

from veil.models.action import Action, DataClassification
from veil.memory.threats import ThreatMemory, ThreatPattern
from veil.memory.feedback import FeedbackEngine, FeedbackRecord, FeedbackType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _action(**kwargs) -> Action:
    defaults = dict(
        agent_id="agent-1",
        session_id="sess-1",
        tool="http",
        operation="request",
        resource="encoded_data",
        destination="https://evil.external.com/drop",
        data_classification=DataClassification.FINANCIAL,
        requested_capability="http.request",
        purpose="Upload data to endpoint.",
        provenance="agent_plan",
    )
    defaults.update(kwargs)
    return Action(**defaults)


def _memory(tmp_path: Path) -> ThreatMemory:
    return ThreatMemory(file_path=tmp_path / "threats.jsonl")


# ---------------------------------------------------------------------------
# ThreatMemory tests
# ---------------------------------------------------------------------------


def test_record_and_query_match(tmp_path):
    mem = _memory(tmp_path)
    action = _action()
    pattern = mem.record_from_action(action, pattern_type="PII_EXFIL", severity="HIGH")

    # Same structural action should match
    results = mem.query(action)
    assert len(results) >= 1
    assert any(r.pattern_id == pattern.pattern_id for r in results)


def test_query_no_match(tmp_path):
    mem = _memory(tmp_path)
    # Record a web exfil pattern
    action = _action()
    mem.record_from_action(action, "PII_EXFIL")

    # Query with a totally different action — internal DB read
    unrelated = _action(
        tool="database",
        operation="read",
        resource="public_docs",
        destination="",
        data_classification=DataClassification.PUBLIC,
    )
    results = mem.query(unrelated)
    assert len(results) == 0


def test_all_patterns(tmp_path):
    mem = _memory(tmp_path)
    mem.record_from_action(_action(), "PII_EXFIL")
    mem.record_from_action(_action(), "PROMPT_INJECTION", severity="CRITICAL")
    all_p = mem.all_patterns()
    assert len(all_p) == 2


def test_persistence(tmp_path):
    path = tmp_path / "threats.jsonl"
    mem1 = ThreatMemory(file_path=path)
    mem1.record_from_action(_action(), "PII_EXFIL")

    # New instance — should read from same file
    mem2 = ThreatMemory(file_path=path)
    assert len(mem2.all_patterns()) == 1


def test_record_direct(tmp_path):
    mem = _memory(tmp_path)
    pattern = ThreatPattern(
        pattern_id="test-id-1",
        pattern_type="PRIVILEGE_ABUSE",
        indicators=["tool:shell", "operation:execute", "classification:SECRET"],
        severity="CRITICAL",
    )
    mem.record(pattern)
    results = mem.all_patterns()
    assert len(results) == 1
    assert results[0].pattern_id == "test-id-1"


# ---------------------------------------------------------------------------
# FeedbackEngine tests
# ---------------------------------------------------------------------------


def test_valid_new_pattern_accepted(tmp_path):
    mem = _memory(tmp_path)
    engine = FeedbackEngine(
        threat_memory=mem,
        feedback_log_path=tmp_path / "feedback.jsonl",
    )
    fb = FeedbackRecord(
        feedback_type=FeedbackType.NEW_PATTERN,
        submitted_by="analyst-1",
        pattern_type="PRIVILEGE_ABUSE",
        indicators=["tool:shell", "operation:execute", "classification:SECRET"],
        severity="CRITICAL",
        notes="Shell execute observed in SupportAgent session.",
    )
    result = engine.submit(fb)
    assert result.accepted is True
    assert result.rejection_reason == ""
    # Should have created a ThreatPattern
    assert len(mem.all_patterns()) == 1


def test_true_positive_adds_to_memory(tmp_path):
    mem = _memory(tmp_path)
    engine = FeedbackEngine(threat_memory=mem, feedback_log_path=tmp_path / "fb.jsonl")
    fb = FeedbackRecord(
        feedback_type=FeedbackType.TRUE_POSITIVE,
        submitted_by="analyst-1",
        pattern_type="PII_EXFIL",
        indicators=["tool:http", "operation:request", "destination_pattern:external_http"],
        severity="HIGH",
    )
    result = engine.submit(fb)
    assert result.accepted
    assert len(mem.all_patterns()) == 1


def test_false_positive_does_not_add_pattern(tmp_path):
    mem = _memory(tmp_path)
    engine = FeedbackEngine(threat_memory=mem, feedback_log_path=tmp_path / "fb.jsonl")
    fb = FeedbackRecord(
        feedback_type=FeedbackType.FALSE_POSITIVE,
        submitted_by="analyst-1",
        pattern_type="PII_EXFIL",
        indicators=["tool:database", "operation:read", "classification:INTERNAL"],
        severity="LOW",
        notes="Legitimate read was incorrectly flagged.",
    )
    result = engine.submit(fb)
    assert result.accepted
    # FALSE_POSITIVE should NOT add to threat memory
    assert len(mem.all_patterns()) == 0


def test_feedback_rejected_no_indicators(tmp_path):
    mem = _memory(tmp_path)
    engine = FeedbackEngine(threat_memory=mem, feedback_log_path=tmp_path / "fb.jsonl")
    fb = FeedbackRecord(
        feedback_type=FeedbackType.NEW_PATTERN,
        submitted_by="analyst-1",
        pattern_type="PII_EXFIL",
        indicators=[],  # empty — invalid
        severity="HIGH",
    )
    result = engine.submit(fb)
    assert not result.accepted
    assert "indicator" in result.rejection_reason.lower()


def test_feedback_rejected_raw_data_in_notes(tmp_path):
    mem = _memory(tmp_path)
    engine = FeedbackEngine(threat_memory=mem, feedback_log_path=tmp_path / "fb.jsonl")
    fb = FeedbackRecord(
        feedback_type=FeedbackType.NEW_PATTERN,
        submitted_by="analyst-1",
        pattern_type="PROMPT_INJECTION",
        indicators=["tool:database", "operation:read"],
        severity="HIGH",
        notes="The agent ran: SELECT * FROM customers WHERE ssn: 123-45-6789",
    )
    result = engine.submit(fb)
    assert not result.accepted
    assert "raw data" in result.rejection_reason.lower()


def test_feedback_rejected_invalid_severity(tmp_path):
    mem = _memory(tmp_path)
    engine = FeedbackEngine(threat_memory=mem, feedback_log_path=tmp_path / "fb.jsonl")
    fb = FeedbackRecord(
        feedback_type=FeedbackType.NEW_PATTERN,
        submitted_by="analyst-1",
        pattern_type="PII_EXFIL",
        indicators=["tool:http"],
        severity="EXTREME",  # invalid
    )
    result = engine.submit(fb)
    assert not result.accepted
    assert "severity" in result.rejection_reason.lower()
