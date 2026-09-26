"""
dashboard/app.py

VEIL Security Dashboard — Streamlit application.

Pages:
  Overview             — aggregate stats + component health
  Live Activity        — auto-refreshing audit event table
  Attack Timeline      — chronological event chain per session
  Threat Investigation — judge reasoning, injection, policy violations
  Capabilities / Policy — agent capability registry
  🔴 Before vs After   — side-by-side: data leaks vs VEIL blocks it

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
# Page: Before vs After  (the main demo page)
# ---------------------------------------------------------------------------

_SCENARIO_META = {
    "p0_attack":          {"label": "💀 P0 Attack — Prompt Injection + Exfiltration",
                           "desc":  "Injected SupportAgent reads customer PII then tries to POST it to attacker.net"},
    "privilege_abuse":    {"label": "🔒 Privilege Abuse — Shell Execution",
                           "desc":  "Agent attempts shell.execute — globally forbidden"},
    "pii_write_attempt":  {"label": "✏️ PII Write — Unauthorised DB Write",
                           "desc":  "SupportAgent tries to write to customer_db — not in its grants"},
    "support_legitimate": {"label": "✅ Legitimate Request",
                           "desc":  "SupportAgent reads a customer record — should be ALLOWED by VEIL"},
    "finance_legitimate": {"label": "💰 Finance Legitimate",
                           "desc":  "FinanceAgent reads payment records — within its grants"},
}


def page_before_after() -> None:
    st.title("🔴 Before VEIL  vs  🛡️ After VEIL")
    st.markdown(
        "Pick a scenario and hit **Run Demo**. "
        "The **left column** shows what happens on a company server with **no security** — "
        "data leaks freely. The **right column** shows the **same request intercepted by VEIL**."
    )

    # ── API connectivity check ──────────────────────────────────────────────
    health = _api_get("/api/v1/health")
    if health is None:
        st.error(
            f"❌ VEIL API not reachable at `{_api_url()}`. "
            "Start it: `uvicorn api.main:app --host 0.0.0.0 --port 8000`"
        )
        return
    st.success("🟢 VEIL API connected")

    st.divider()

    # ── Scenario picker ─────────────────────────────────────────────────────
    scenario_labels = {v["label"]: k for k, v in _SCENARIO_META.items()}
    chosen_label = st.selectbox(
        "Choose a scenario",
        options=list(scenario_labels.keys()),
        index=0,
    )
    chosen_scenario = scenario_labels[chosen_label]
    st.markdown(f"_{_SCENARIO_META[chosen_scenario]['desc']}_")

    run = st.button("🚀 Run Demo", type="primary", use_container_width=True)

    if not run:
        st.info("Select a scenario above and click **Run Demo** to start.")
        return

    # ── Run both sides simultaneously ───────────────────────────────────────
    with st.spinner("Running both sides…"):
        vuln_result     = _api_post("/vulnerable/attack",     {"scenario": chosen_scenario})
        protected_result = _api_post("/api/v1/attacks/run",   {"scenario": chosen_scenario})

    # ── Side-by-side layout ─────────────────────────────────────────────────
    col_vuln, col_prot = st.columns(2, gap="large")

    # ════════════════════════════════
    # LEFT — Vulnerable server
    # ════════════════════════════════
    with col_vuln:
        st.markdown(
            '<div style="background:#7f1d1d;color:#fff;padding:10px 16px;'
            'border-radius:8px;font-weight:700;font-size:1.1em;margin-bottom:12px;">'
            '🔴 WITHOUT VEIL — No Security Controls'
            '</div>',
            unsafe_allow_html=True,
        )

        if vuln_result is None or "error" in (vuln_result or {}):
            st.error(f"API error: {(vuln_result or {}).get('error','No response')}")
        else:
            steps = vuln_result.get("steps", [])
            total = len(steps)
            executed = vuln_result.get("steps_executed", total)
            st.markdown(
                f'<p style="color:#ef4444;font-weight:600;">'
                f'⚠️ {executed}/{total} steps EXECUTED — attacker succeeds</p>',
                unsafe_allow_html=True,
            )
            for step in steps:
                _render_vuln_step(step)

    # ════════════════════════════════
    # RIGHT — VEIL protected
    # ════════════════════════════════
    with col_prot:
        st.markdown(
            '<div style="background:#14532d;color:#fff;padding:10px 16px;'
            'border-radius:8px;font-weight:700;font-size:1.1em;margin-bottom:12px;">'
            '🛡️ WITH VEIL — Every Step Enforced'
            '</div>',
            unsafe_allow_html=True,
        )

        if protected_result is None or "error" in (protected_result or {}):
            st.error(f"API error: {(protected_result or {}).get('error','No response')}")
        else:
            steps = protected_result.get("steps", [])
            blocked = sum(1 for s in steps if not s.get("executed"))
            color   = "#22c55e" if blocked > 0 else "#64748b"
            st.markdown(
                f'<p style="color:{color};font-weight:600;">'
                f'🛡️ {blocked}/{len(steps)} steps BLOCKED by VEIL</p>',
                unsafe_allow_html=True,
            )
            for step in steps:
                _render_prot_step(step)

    # ── Summary banner ──────────────────────────────────────────────────────
    st.divider()
    v_steps = (vuln_result or {}).get("steps_executed", "?")
    p_steps = sum(
        1 for s in (protected_result or {}).get("steps", []) if not s.get("executed")
    )
    c1, c2 = st.columns(2)
    c1.error(f"🔴 Without VEIL: **{v_steps} step(s) executed** — data exposed")
    c2.success(f"🛡️ With VEIL: **{p_steps} step(s) blocked** — data protected")


def _render_vuln_step(step: dict) -> None:
    """Render one step from the vulnerable (no-VEIL) run."""
    tool_op  = f"{step.get('tool','')}.{step.get('operation','')}"
    resource = step.get("resource", "")
    executed = step.get("executed", False)
    output   = step.get("output", {})
    purpose  = (step.get("purpose") or "")[:120]

    header_color = "#7f1d1d" if executed else "#374151"
    status_text  = "EXECUTED ✓" if executed else "failed"

    st.markdown(
        f'<div style="border:1px solid #ef4444;border-radius:6px;'
        f'padding:10px 14px;margin-bottom:10px;background:#1c0a0a;">'
        f'<b style="color:#ef4444;">Step {step["step"]} — {tool_op}</b>'
        f'<span style="float:right;background:#ef4444;color:#fff;'
        f'padding:1px 8px;border-radius:10px;font-size:0.8em;">{status_text}</span>'
        f'<br><span style="color:#9ca3af;font-size:0.85em;">→ {resource}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    if purpose:
        st.markdown(f"<span style='color:#9ca3af;font-size:0.83em;'>Purpose: {purpose}</span>",
                    unsafe_allow_html=True)

    if executed and output:
        # Show leaked data prominently
        rows = output.get("rows", [])
        if rows:
            st.markdown(
                f'<div style="background:#3b0a0a;border-left:3px solid #ef4444;'
                f'padding:8px 12px;border-radius:4px;margin-top:6px;">'
                f'<b style="color:#ef4444;">💀 DATA LEAKED — {len(rows)} record(s)</b>'
                f'</div>',
                unsafe_allow_html=True,
            )
            for row in rows:
                st.markdown(
                    f'<div style="font-family:monospace;font-size:0.82em;'
                    f'color:#fca5a5;padding:2px 0;">{json.dumps(row)}</div>',
                    unsafe_allow_html=True,
                )
        elif output.get("status_code"):
            st.markdown(
                f'<div style="color:#fca5a5;font-size:0.85em;">'
                f'HTTP {output["status_code"]} → {output.get("response_body","")[:80]}'
                f'</div>',
                unsafe_allow_html=True,
            )
        elif output.get("content"):
            st.markdown(
                f'<div style="color:#fca5a5;font-size:0.85em;">'
                f'Content: {str(output["content"])[:120]}'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<div style="color:#fca5a5;font-size:0.85em;">'
                f'{json.dumps(output)[:120]}'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("<div style='margin-bottom:4px'></div>", unsafe_allow_html=True)


def _render_prot_step(step: dict) -> None:
    """Render one step from the VEIL-protected run."""
    tool_op   = f"{step.get('tool','')}.{step.get('operation','')}"
    resource  = step.get("resource", "")
    decision  = step.get("decision", "UNKNOWN")
    reason    = (step.get("reason") or "")[:150]
    executed  = step.get("executed", False)
    revoked   = step.get("revoked_capability")
    rules     = step.get("triggered_rules", [])
    injected  = step.get("injection_detected", False)

    d_color = _DECISION_COLORS.get(decision, "#64748b")
    bg      = "#0a1f0a" if not executed else "#0a1a0a"
    border  = d_color

    st.markdown(
        f'<div style="border:1px solid {border};border-radius:6px;'
        f'padding:10px 14px;margin-bottom:10px;background:{bg};">'
        f'<b style="color:{d_color};">Step {step["step"]} — {tool_op}</b>'
        f'<span style="float:right;background:{d_color};color:#fff;'
        f'padding:1px 8px;border-radius:10px;font-size:0.8em;">{decision}</span>'
        f'<br><span style="color:#9ca3af;font-size:0.85em;">→ {resource}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    exec_text = "✅ Executed (permitted)" if executed else "🚫 Blocked — tool never ran"
    exec_color = "#22c55e" if executed else "#ef4444"
    st.markdown(
        f'<span style="color:{exec_color};font-size:0.9em;font-weight:600;">'
        f'{exec_text}</span>',
        unsafe_allow_html=True,
    )

    if reason:
        box_color = "#1a0a0a" if decision in ("BLOCK","REVOKE") else "#0a1a0a"
        st.markdown(
            f'<div style="background:{box_color};border-left:3px solid {d_color};'
            f'padding:6px 10px;border-radius:4px;margin-top:6px;'
            f'font-size:0.85em;color:#d1d5db;">'
            f'🧠 {reason}'
            f'</div>',
            unsafe_allow_html=True,
        )

    if injected:
        st.markdown(
            '<div style="color:#fbbf24;font-size:0.82em;margin-top:4px;">'
            '🚨 Injection signal detected in payload</div>',
            unsafe_allow_html=True,
        )
    if rules:
        st.markdown(
            f'<div style="color:#94a3b8;font-size:0.8em;margin-top:4px;">'
            f'Rules: {", ".join(rules)}</div>',
            unsafe_allow_html=True,
        )
    if revoked:
        st.markdown(
            f'<div style="color:#ef4444;font-weight:600;font-size:0.85em;margin-top:4px;">'
            f'🔒 Capability REVOKED: {revoked}</div>',
            unsafe_allow_html=True,
        )

    if executed and step.get("execution_output"):
        out = step["execution_output"]
        rows = out.get("rows", [])
        if rows:
            st.markdown(
                f'<div style="color:#86efac;font-size:0.83em;margin-top:4px;">'
                f'Output: {len(rows)} row(s) returned (permitted read)</div>',
                unsafe_allow_html=True,
            )

    st.markdown("<div style='margin-bottom:4px'></div>", unsafe_allow_html=True)


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
            "🔴 Before vs After",
            "Live Activity",
            "Attack Timeline",
            "Threat Investigation",
            "Capabilities / Policy",
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
    elif page == "🔴 Before vs After":
        page_before_after()
    elif page == "Live Activity":
        page_live_activity(records)
    elif page == "Attack Timeline":
        page_attack_timeline(records)
    elif page == "Threat Investigation":
        page_threat_investigation(records, threat_records)
    elif page == "Capabilities / Policy":
        page_capabilities()


if __name__ == "__main__":
    main()
