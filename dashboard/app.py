"""
dashboard/app.py

VEIL Security Dashboard — Streamlit application.

Reads from the audit JSONL file and threat memory to visualize security activity.
All data is read-only — the dashboard never writes to the pipeline.

Pages:
  Overview          — aggregate stats (protected status, totals, threats, revocations)
  Live Activity     — auto-refreshing table of recent audit events
  Attack Timeline   — chronological event chain for a selected session
  Threat Investigation — detailed view with injection/trajectory/judge findings
  Capabilities / Policy — static view of agent capability registry
  Attack Lab        — trigger real pipeline calls via API buttons

Run:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import streamlit as st

# ---------------------------------------------------------------------------
# Path resolution: make veil package importable when run from repo root
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv
load_dotenv(dotenv_path=_REPO_ROOT / ".env", override=False)

from veil.config import settings

# ---------------------------------------------------------------------------
# Capability registry (static view — mirrors veil/security/capabilities.py)
# Used even before Sub-task 4 is wired.
# ---------------------------------------------------------------------------

AGENT_CAPABILITIES = {
    "SupportAgent": {
        "goal": "Handle customer support queries; read and respond to customer data.",
        "allowed": ["database.read", "email.read", "email.send", "file.read"],
        "denied": ["database.write", "shell.execute", "http.request", "file.write"],
    },
    "ResearchAgent": {
        "goal": "Research internal documents and public web sources.",
        "allowed": ["file.read", "http.request", "database.read"],
        "denied": ["database.write", "shell.execute", "email.send"],
    },
    "FinanceAgent": {
        "goal": "Process financial reports; read payment and employee records.",
        "allowed": ["database.read", "file.read", "file.write"],
        "denied": ["shell.execute", "http.request", "email.send", "database.write"],
    },
}

# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------


def _load_audit_records(path: Path) -> list[dict]:
    """Load all audit records from the JSONL file."""
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _load_threat_patterns(path: Path) -> list[dict]:
    """Load all threat patterns from the JSONL file."""
    if not path.exists():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            patterns.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return patterns


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

_DECISION_COLORS = {
    "ALLOW": "#22c55e",
    "WARN": "#f59e0b",
    "REQUIRE_APPROVAL": "#8b5cf6",
    "BLOCK": "#ef4444",
    "REVOKE": "#dc2626",
}

_RISK_COLORS = {
    "NONE": "#94a3b8",
    "LOW": "#22c55e",
    "MEDIUM": "#f59e0b",
    "HIGH": "#ef4444",
    "CRITICAL": "#dc2626",
}


def _badge(text: str, color: str) -> str:
    return (
        f'<span style="background:{color};color:#fff;padding:2px 10px;'
        f'border-radius:12px;font-size:0.82em;font-weight:600;">{text}</span>'
    )


def _decision_badge(decision: str) -> str:
    color = _DECISION_COLORS.get(decision.upper(), "#64748b")
    return _badge(decision, color)


def _risk_badge(level: str) -> str:
    color = _RISK_COLORS.get(level.upper(), "#64748b")
    return _badge(level, color)


# ---------------------------------------------------------------------------
# Page: Overview
# ---------------------------------------------------------------------------


def page_overview(records: list[dict]) -> None:
    st.title("VEIL Security Dashboard")
    st.markdown("**Verifiable Execution Isolation Layer** — IBM Bob 2.0 Hackathon")
    st.divider()

    total = len(records)
    allowed = sum(1 for r in records if r.get("decision") == "ALLOW")
    warned = sum(1 for r in records if r.get("decision") == "WARN")
    blocked = sum(1 for r in records if r.get("decision") in ("BLOCK", "REQUIRE_APPROVAL"))
    revoked = sum(1 for r in records if r.get("decision") == "REVOKE")
    threats = sum(1 for r in records if r.get("decision") not in ("ALLOW",))

    # Protected status banner
    if total == 0:
        st.info("No audit events yet. Run the attacker simulator or a scenario to generate data.")
    elif blocked + revoked > 0:
        st.success("**VEIL ACTIVE** — Threats detected and blocked.")
    else:
        st.info("VEIL active. No blocks recorded yet.")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Actions", total)
    c2.metric("Allowed", allowed)
    c3.metric("Warned", warned)
    c4.metric("Blocked", blocked)
    c5.metric("Revocations", revoked)

    st.divider()

    if total > 0:
        # Decision distribution chart
        import pandas as pd
        decision_counts = {}
        for r in records:
            d = r.get("decision", "UNKNOWN")
            decision_counts[d] = decision_counts.get(d, 0) + 1

        df = pd.DataFrame(
            {"Decision": list(decision_counts.keys()), "Count": list(decision_counts.values())}
        )
        df = df.sort_values("Count", ascending=False)
        st.subheader("Decision Distribution")
        st.bar_chart(df.set_index("Decision"))

        # Recent threats
        threat_records = [r for r in records if r.get("decision") not in ("ALLOW",)]
        if threat_records:
            st.subheader("Recent Security Events")
            _render_events_table(threat_records[-10:][::-1])


# ---------------------------------------------------------------------------
# Page: Live Activity
# ---------------------------------------------------------------------------


def page_live_activity(records: list[dict]) -> None:
    st.title("Live Activity")
    st.markdown("All intercepted actions in reverse-chronological order.")

    col1, col2 = st.columns([3, 1])
    with col2:
        auto_refresh = st.checkbox("Auto-refresh (3s)", value=False)
    with col1:
        filter_decision = st.multiselect(
            "Filter by decision",
            options=["ALLOW", "WARN", "REQUIRE_APPROVAL", "BLOCK", "REVOKE"],
            default=[],
        )

    if filter_decision:
        filtered = [r for r in records if r.get("decision") in filter_decision]
    else:
        filtered = records

    if not filtered:
        st.info("No events to display.")
        return

    _render_events_table(filtered[::-1])

    if auto_refresh:
        import time
        time.sleep(3)
        st.rerun()


def _render_events_table(records: list[dict]) -> None:
    import pandas as pd

    rows = []
    for r in records:
        rows.append(
            {
                "Timestamp": r.get("timestamp", "")[:19].replace("T", " "),
                "Agent": r.get("agent_id", ""),
                "Session": (r.get("session_id", "") or "")[:8] + "…",
                "Tool": r.get("tool", ""),
                "Operation": r.get("operation", ""),
                "Resource": r.get("resource", ""),
                "Risk": r.get("risk_level", ""),
                "Decision": r.get("decision", ""),
                "Reason": (r.get("reason", "") or "")[:80],
            }
        )
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, height=400)


# ---------------------------------------------------------------------------
# Page: Attack Timeline
# ---------------------------------------------------------------------------


def page_attack_timeline(records: list[dict]) -> None:
    st.title("Attack Timeline")
    st.markdown("Chronological action chain for a selected session.")

    sessions = sorted(set(r.get("session_id", "") for r in records if r.get("session_id")))
    if not sessions:
        st.info("No session data available.")
        return

    selected = st.selectbox("Select Session", sessions)
    session_records = [r for r in records if r.get("session_id") == selected]
    session_records.sort(key=lambda r: r.get("timestamp", ""))

    st.markdown(f"**{len(session_records)} actions** in session `{selected}`")
    st.divider()

    for i, r in enumerate(session_records, start=1):
        decision = r.get("decision", "UNKNOWN")
        risk = r.get("risk_level", "NONE")
        color = _DECISION_COLORS.get(decision, "#64748b")
        ts = r.get("timestamp", "")[:19].replace("T", " ")

        with st.expander(
            f"Step {i} — {r.get('tool', '')}.{r.get('operation', '')} → "
            f"{r.get('resource', '')}  [{decision}]",
            expanded=(decision not in ("ALLOW",)),
        ):
            col1, col2, col3 = st.columns(3)
            col1.markdown(f"**Agent:** {r.get('agent_id', '')}")
            col2.markdown(f"**Timestamp:** {ts}")
            col3.markdown(
                f"**Decision:** {_decision_badge(decision)}  **Risk:** {_risk_badge(risk)}",
                unsafe_allow_html=True,
            )
            st.markdown(f"**Reason:** {r.get('reason', '')}")

            if r.get("triggered_rules"):
                st.markdown(f"**Triggered rules:** `{'`, `'.join(r['triggered_rules'])}`")
            if r.get("destination"):
                st.markdown(f"**Destination:** `{r['destination']}`")
            if r.get("purpose"):
                st.markdown(f"**Declared purpose:** _{r['purpose'][:200]}_")


# ---------------------------------------------------------------------------
# Page: Threat Investigation
# ---------------------------------------------------------------------------


def page_threat_investigation(records: list[dict], threat_records: list[dict]) -> None:
    st.title("Threat Investigation")

    tab1, tab2 = st.tabs(["Security Decisions", "Known Threat Patterns"])

    with tab1:
        suspicious = [
            r for r in records
            if r.get("decision") not in ("ALLOW",)
        ]
        if not suspicious:
            st.info("No suspicious events recorded.")
        else:
            for r in suspicious[::-1][:20]:
                decision = r.get("decision", "UNKNOWN")
                with st.expander(
                    f"[{decision}] {r.get('agent_id', '')} — "
                    f"{r.get('tool', '')}.{r.get('operation', '')} "
                    f"@ {r.get('timestamp', '')[:19]}",
                    expanded=decision in ("BLOCK", "REVOKE"),
                ):
                    _render_detail(r)

    with tab2:
        if not threat_records:
            st.info("No threat patterns in memory.")
        else:
            for p in threat_records[::-1][:20]:
                sev = p.get("severity", "UNKNOWN")
                color = _RISK_COLORS.get(sev.upper(), "#64748b")
                with st.expander(
                    f"[{sev}] {p.get('pattern_type', '')} — "
                    f"seen {p.get('occurrence_count', 1)}x",
                    expanded=False,
                ):
                    st.markdown(
                        f"**Severity:** {_risk_badge(sev)}", unsafe_allow_html=True
                    )
                    st.markdown(f"**First seen:** {str(p.get('first_seen', ''))[:19]}")
                    st.markdown(f"**Last seen:** {str(p.get('last_seen', ''))[:19]}")
                    st.markdown("**Indicators:**")
                    for ind in p.get("indicators", []):
                        st.markdown(f"  - `{ind}`")


def _render_detail(r: dict) -> None:
    cols = st.columns(3)
    cols[0].markdown(f"**Agent:** {r.get('agent_id', '')}")
    cols[1].markdown(f"**Tool:** {r.get('tool', '')}.{r.get('operation', '')}")
    cols[2].markdown(
        f"**Decision:** {_decision_badge(r.get('decision', ''))}",
        unsafe_allow_html=True,
    )

    # Judge reasoning — most compelling part of the demo; shown prominently
    if r.get("reason"):
        decision = r.get("decision", "")
        if decision in ("BLOCK", "REVOKE", "REQUIRE_APPROVAL", "WARN"):
            st.error(f"🧠 **Judge Reasoning:** {r['reason']}")
        else:
            st.success(f"🧠 **Judge Reasoning:** {r['reason']}")

    if r.get("triggered_rules"):
        st.markdown(f"**Rules:** `{'`, `'.join(r['triggered_rules'])}`")
    if r.get("risk_level"):
        st.markdown(
            f"**Risk:** {_risk_badge(r['risk_level'])}",
            unsafe_allow_html=True,
        )
    if r.get("injection_detected"):
        st.warning("🚨 **Injection detected** in this action.")
    if r.get("policy_violated_rules"):
        st.markdown(f"**Policy violations:** `{'`, `'.join(r['policy_violated_rules'])}`")
    if r.get("data_classification"):
        st.markdown(f"**Data classification:** `{r['data_classification']}`")
    if r.get("revoked_capability"):
        st.error(f"🔒 **Revoked capability:** `{r['revoked_capability']}`")


# ---------------------------------------------------------------------------
# Page: Capabilities / Policy
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# API helper
# ---------------------------------------------------------------------------


def _api_url() -> str:
    return settings.veil_api_url.rstrip("/")


def _api_get(path: str) -> Optional[dict | list]:
    try:
        resp = httpx.get(f"{_api_url()}{path}", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        return None


def _api_post(path: str, payload: dict) -> Optional[dict | list]:
    try:
        resp = httpx.post(f"{_api_url()}{path}", json=payload, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Page: Attack Lab
# ---------------------------------------------------------------------------

_SCENARIO_META = {
    "support_legitimate":   {"label": "✅ Legitimate Request",    "desc": "SupportAgent reads customer record — should ALLOW"},
    "p0_attack":            {"label": "💀 P0 Attack Chain",        "desc": "Injection → PII read → exfiltration → REVOKE"},
    "privilege_abuse":      {"label": "🔒 Privilege Abuse",        "desc": "Shell execution attempt — globally forbidden"},
    "pii_write_attempt":    {"label": "✏️ PII Write Attempt",      "desc": "Unauthorised write to customer_db — BLOCK"},
    "finance_legitimate":   {"label": "💰 Finance Legitimate",     "desc": "FinanceAgent reads payment records — ALLOW"},
}


def page_attack_lab() -> None:
    st.title("⚔️ Attack Lab")
    st.markdown(
        "Trigger real pipeline calls through the VEIL API. "
        "Results are live — no prerecorded data."
    )

    # API health check
    health = _api_get("/api/v1/health")
    if health is None:
        st.error(
            f"⚠️ VEIL API not reachable at `{_api_url()}`. "
            "Start it with: `uvicorn api.main:app --port 8000`"
        )
    else:
        overall = health.get("status", "unknown")
        if overall == "ok":
            st.success(f"🟢 VEIL API connected — all components healthy")
        else:
            st.warning(f"🟡 VEIL API connected but some components degraded")

    st.divider()

    # Before/After toggle
    mode = st.radio(
        "Demo Mode",
        options=["🛡️ After VEIL (Gateway enforces)", "⚠️ Before VEIL (Direct — no gateway)"],
        horizontal=True,
        key="attack_lab_mode",
    )
    use_veil = mode.startswith("🛡️")

    st.divider()
    st.subheader("Attack Scenarios")

    for scenario_name, meta in _SCENARIO_META.items():
        col1, col2 = st.columns([1, 3])
        with col1:
            run = st.button(meta["label"], key=f"btn_{scenario_name}", use_container_width=True)
        with col2:
            st.markdown(f"_{meta['desc']}_")

        if run:
            if use_veil:
                _run_scenario_via_api(scenario_name)
            else:
                _run_scenario_direct(scenario_name)


def _run_scenario_via_api(scenario_name: str) -> None:
    """Run a named scenario via the VEIL API and render results."""
    with st.spinner(f"Running `{scenario_name}` through VEIL…"):
        result = _api_post("/api/v1/attacks/run", {"scenario": scenario_name})

    if result is None or "error" in result:
        st.error(f"API error: {result.get('error') if result else 'No response'}")
        return

    steps = result.get("steps", [])
    session_id = result.get("session_id", "")
    st.markdown(f"**Session:** `{session_id}` — **{len(steps)} step(s)**")

    for step in steps:
        decision = step.get("decision", "UNKNOWN")
        color = _DECISION_COLORS.get(decision, "#64748b")
        badge_html = _decision_badge(decision)
        risk_html = _risk_badge(step.get("risk_level", "NONE"))

        with st.expander(
            f"Step {step['step']} — {step['tool']}.{step['operation']} → {step['resource']}  [{decision}]",
            expanded=(decision not in ("ALLOW",)),
        ):
            c1, c2, c3 = st.columns(3)
            c1.markdown(f"**Decision:** {badge_html}", unsafe_allow_html=True)
            c2.markdown(f"**Risk:** {risk_html}", unsafe_allow_html=True)
            c3.markdown(f"**Executed:** {'Yes ✅' if step.get('executed') else 'No 🚫'}")

            reason = step.get("reason", "")
            if decision in ("BLOCK", "REVOKE", "REQUIRE_APPROVAL"):
                st.error(f"🧠 **Reason:** {reason}")
            elif decision == "WARN":
                st.warning(f"🧠 **Reason:** {reason}")
            else:
                st.success(f"🧠 **Reason:** {reason}")

            if step.get("triggered_rules"):
                st.markdown(f"**Rules fired:** `{'`, `'.join(step['triggered_rules'])}`")
            if step.get("injection_detected"):
                st.warning("🚨 Injection detected")
            if step.get("revoked_capability"):
                st.error(f"🔒 Capability revoked: `{step['revoked_capability']}`")
            if step.get("execution_output"):
                with st.expander("Tool output"):
                    st.json(step["execution_output"])


def _run_scenario_direct(scenario_name: str) -> None:
    """Run scenario directly (no gateway) — Before VEIL mode."""
    from simulator.client.scenarios import SCENARIOS
    from simulator.client.tools import dispatch

    scenario_fn = SCENARIOS.get(scenario_name)
    if scenario_fn is None:
        st.error(f"Unknown scenario: {scenario_name}")
        return

    session_id = f"direct-{scenario_name}-{uuid.uuid4().hex[:6]}"
    actions = scenario_fn(session_id=session_id)

    st.warning(f"⚠️ Running WITHOUT VEIL — {len(actions)} action(s) dispatched directly to tool stubs")
    st.markdown(f"**Session:** `{session_id}`")

    for i, action in enumerate(actions, start=1):
        with st.expander(
            f"Step {i} — {action.tool}.{action.operation} → {action.resource}  [UNPROTECTED]",
            expanded=True,
        ):
            st.markdown(f"**Mode:** ⚠️ No VEIL gateway")
            try:
                output = dispatch(action)
                st.success("✅ Tool executed (no enforcement)")
                st.json(output)
            except Exception as exc:
                st.error(f"Tool error: {exc}")


# ---------------------------------------------------------------------------
# Page: Capabilities / Policy
# ---------------------------------------------------------------------------


def page_capabilities() -> None:
    st.title("Capabilities & Policy")
    st.markdown("Live view of agent capability grants from the CapabilityManager registry.")
    st.divider()

    from veil.security.capabilities import CapabilityManager
    mgr = CapabilityManager()
    profiles = mgr.all_profiles()

    for profile in profiles:
        with st.expander(f"**{profile.agent_id}**", expanded=True):
            st.markdown(f"**Description:** {profile.description}")
            st.markdown("**Grants:**")
            for g in profile.grants:
                ops = ", ".join(sorted(g.operations))
                resources = ", ".join(sorted(g.resources))
                st.markdown(f"  - `{g.tool}` — ops: `{ops}` — resources: `{resources}`")

    st.divider()
    st.subheader("Hard Policy Rules")
    rules = [
        ("POLICY_PII_TO_EXTERNAL", "Sensitive/PII data must not be sent to external HTTP endpoints."),
        ("POLICY_SHELL_FORBIDDEN", "shell.execute is globally forbidden for all agents."),
        ("POLICY_FORBIDDEN_OPERATION", "execute/spawn operations are globally forbidden."),
        ("POLICY_CREDENTIAL_ACCESS_UNREGISTERED", "CREDENTIAL/SECRET resources accessed by unregistered agents."),
        ("POLICY_WRITE_TO_SENSITIVE_RESOURCE", "Write to sensitive resource — escalates to risk engine."),
        ("POLICY_EXTERNAL_HTTP_FROM_NON_RESEARCH", "External HTTP from agent without explicit grant."),
        ("POLICY_SUSPICIOUS_PROVENANCE", "external_content provenance — escalates to risk engine."),
    ]
    for rule_id, description in rules:
        st.markdown(f"- **`{rule_id}`** — {description}")


# ---------------------------------------------------------------------------
# App entry point
# ---------------------------------------------------------------------------


def _render_health_indicators() -> None:
    """Show per-component health from the API on the Overview page."""
    health = _api_get("/api/v1/health")
    if health is None:
        st.warning(f"⚠️ VEIL API not reachable at `{_api_url()}`")
        return

    components = health.get("components", {})
    cols = st.columns(len(components))
    for col, (name, info) in zip(cols, components.items()):
        status = info.get("status", "unknown")
        icon = "🟢" if status == "ok" else ("🟡" if status == "warning" else "🔴")
        col.metric(label=f"{icon} {name.capitalize()}", value=status.upper())


def main() -> None:
    st.set_page_config(
        page_title="VEIL Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Load data
    audit_path = settings.audit_file_path
    threat_path = settings.threat_memory_path

    records = _load_audit_records(audit_path)
    threat_records = _load_threat_patterns(threat_path)

    # Sidebar
    st.sidebar.title("🛡️ VEIL")
    st.sidebar.markdown("*Verifiable Execution Isolation Layer*")
    st.sidebar.divider()

    page = st.sidebar.radio(
        "Navigate",
        options=[
            "Overview",
            "Live Activity",
            "Attack Timeline",
            "Threat Investigation",
            "Capabilities / Policy",
            "⚔️ Attack Lab",
        ],
    )

    st.sidebar.divider()
    st.sidebar.markdown(f"**API URL:** `{_api_url()}`")
    st.sidebar.markdown(f"**Audit file:** `{audit_path}`")
    st.sidebar.markdown(f"**Events loaded:** {len(records)}")
    st.sidebar.markdown(f"**Threat patterns:** {len(threat_records)}")

    if st.sidebar.button("Refresh Data"):
        st.rerun()

    # Route to page
    if page == "Overview":
        _render_health_indicators()
        st.divider()
        page_overview(records)
    elif page == "Live Activity":
        page_live_activity(records)
    elif page == "Attack Timeline":
        page_attack_timeline(records)
    elif page == "Threat Investigation":
        page_threat_investigation(records, threat_records)
    elif page == "Capabilities / Policy":
        page_capabilities()
    elif page == "⚔️ Attack Lab":
        page_attack_lab()


if __name__ == "__main__":
    main()
