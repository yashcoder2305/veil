"""
tests/intelligence/test_revocation.py
"""
from __future__ import annotations

import pytest
from veil.agents.revocation import RevocationEngine


def test_revoke_and_check():
    engine = RevocationEngine()
    engine.revoke("agent-1", "sess-1", "database.read", "Test revocation")
    assert engine.is_revoked("agent-1", "sess-1", "database.read")
    assert not engine.is_revoked("agent-1", "sess-1", "http.request")


def test_revoke_idempotent():
    engine = RevocationEngine()
    r1 = engine.revoke("agent-1", "sess-1", "database.read")
    r2 = engine.revoke("agent-1", "sess-1", "database.read")
    assert r1 is r2


def test_session_isolation():
    engine = RevocationEngine()
    engine.revoke("agent-1", "sess-A", "database.read")
    assert not engine.is_revoked("agent-1", "sess-B", "database.read")


def test_get_record():
    engine = RevocationEngine()
    engine.revoke("agent-1", "sess-1", "http.request", "Exfil detected")
    record = engine.get_record("agent-1", "sess-1", "http.request")
    assert record is not None
    assert record.reason == "Exfil detected"
    assert record.capability == "http.request"


def test_list_revocations_filtered():
    engine = RevocationEngine()
    engine.revoke("agent-1", "sess-1", "database.read")
    engine.revoke("agent-1", "sess-1", "http.request")
    engine.revoke("agent-2", "sess-1", "file.write")
    
    all_sess = engine.list_revocations(session_id="sess-1")
    assert len(all_sess) == 3
    
    agent1_only = engine.list_revocations(session_id="sess-1", agent_id="agent-1")
    assert len(agent1_only) == 2


def test_clear_session():
    engine = RevocationEngine()
    engine.revoke("agent-1", "sess-1", "database.read")
    engine.revoke("agent-1", "sess-2", "database.read")
    removed = engine.clear_session("sess-1")
    assert removed == 1
    assert not engine.is_revoked("agent-1", "sess-1", "database.read")
    assert engine.is_revoked("agent-1", "sess-2", "database.read")
