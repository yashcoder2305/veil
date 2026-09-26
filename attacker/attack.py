"""
attacker/attack.py

Run this on the ATTACKER'S laptop.
Only requires:  pip install httpx

Usage:
    python attack.py
"""

import httpx
import json
import sys

HOST = "http://192.168.1.4:8000"

# ── colours ───────────────────────────────────────────────────────────────

def red(t):    return f"\033[91m{t}\033[0m"
def green(t):  return f"\033[92m{t}\033[0m"
def yellow(t): return f"\033[93m{t}\033[0m"
def bold(t):   return f"\033[1m{t}\033[0m"
def dim(t):    return f"\033[2m{t}\033[0m"

def section(title):
    print("\n" + bold("=" * 64))
    print(bold(f"  {title}"))
    print(bold("=" * 64))


# ── connectivity check ─────────────────────────────────────────────────────

def check_connection():
    try:
        r = httpx.get(f"{HOST}/api/v1/health", timeout=5)
        print(green(f"  Connected to VEIL server at {HOST}"))
    except Exception as e:
        print(red(f"  Cannot reach {HOST} — is the server running?"))
        print(red(f"  Error: {e}"))
        sys.exit(1)


# ── Phase 1: No VEIL ──────────────────────────────────────────────────────

def phase_vulnerable():
    section("PHASE 1 — Company server WITHOUT VEIL  (no security)")
    print(dim(f"  Target : {HOST}/vulnerable/attack"))
    print(dim( "  Attack : p0_attack  (prompt injection + data exfiltration)\n"))

    try:
        r = httpx.post(
            f"{HOST}/vulnerable/attack",
            json={"scenario": "p0_attack"},
            timeout=15,
        )
        data = r.json()
    except Exception as e:
        print(red(f"  Request failed: {e}"))
        return

    steps          = data.get("steps", [])
    steps_executed = data.get("steps_executed", 0)

    print(red(f"  ⚠️  WARNING : {data.get('warning','')}"))
    print(red(f"  RESULT    : {steps_executed}/{len(steps)} steps EXECUTED — attacker wins\n"))

    for step in steps:
        tool_op  = f"{step['tool']}.{step['operation']}"
        resource = step.get("resource", "")
        executed = step.get("executed", False)
        output   = step.get("output") or {}
        purpose  = (step.get("purpose") or "")[:90]

        status = red("EXECUTED ✓") if executed else yellow("failed")
        print(f"  Step {step['step']}  {bold(tool_op):<28}  →  {resource}")
        print(f"         Purpose  : {dim(purpose)}")
        print(f"         Status   : {status}")

        rows = output.get("rows", [])
        if rows:
            print(red(f"         💀 DATA LEAKED — {len(rows)} record(s):"))
            for row in rows:
                print(red(f"            {json.dumps(row)}"))

        elif output.get("status_code"):
            print(red(f"         HTTP {output['status_code']} → {output.get('response_body','')[:70]}"))

        elif output.get("content"):
            print(red(f"         Content : {str(output['content'])[:80]}"))

        print()

    print(red("  Customer PII was read and sent to attacker.net — no alert, no audit trail."))


# ── Phase 2: VEIL active ───────────────────────────────────────────────────

def phase_protected():
    section("PHASE 2 — Same server WITH VEIL  (every step enforced)")
    print(dim(f"  Target : {HOST}/api/v1/attacks/run"))
    print(dim( "  Attack : p0_attack  (identical payload)\n"))

    try:
        r = httpx.post(
            f"{HOST}/api/v1/attacks/run",
            json={"scenario": "p0_attack"},
            timeout=60,
        )
        data = r.json()
    except Exception as e:
        print(red(f"  Request failed: {e}"))
        return

    steps   = data.get("steps", [])
    blocked = sum(1 for s in steps if not s.get("executed"))

    icons = {
        "ALLOW":            green("✅ ALLOW"),
        "WARN":             yellow("⚠️  WARN"),
        "BLOCK":            red("🚫 BLOCK"),
        "REVOKE":           red("🔒 REVOKE"),
        "REQUIRE_APPROVAL": yellow("🔔 REQUIRE_APPROVAL"),
    }

    for step in steps:
        tool_op   = f"{step['tool']}.{step['operation']}"
        resource  = step.get("resource", "")
        decision  = step.get("decision", "?")
        reason    = (step.get("reason") or "")[:110]
        executed  = step.get("executed", False)
        revoked   = step.get("revoked_capability")
        rules     = step.get("triggered_rules", [])
        injected  = step.get("injection_detected", False)

        label    = icons.get(decision, f"❓ {decision}")
        exec_str = green("Yes") if executed else red("No — blocked by VEIL")

        print(f"  Step {step['step']}  {bold(tool_op):<28}  →  {resource}")
        print(f"         Decision  : {label}")
        print(f"         Executed  : {exec_str}")
        print(f"         Reason    : {dim(reason)}")

        if injected:
            print(red("         🚨 Injection signal detected in payload"))
        if rules:
            print(dim(f"         Rules     : {', '.join(rules)}"))
        if revoked:
            print(red(f"         🔒 Capability REVOKED for this session: {revoked}"))

        print()

    print(green(f"  {blocked}/{len(steps)} steps BLOCKED — customer PII never left the server."))
    print(green("  Full audit trail written. Judge reasoning recorded."))


# ── Summary ────────────────────────────────────────────────────────────────

def summary():
    section("SUMMARY")
    print(f"  {red('WITHOUT VEIL')} : attacker read customer PII and exfiltrated it — nothing stopped it")
    print(f"  {green('WITH VEIL')}    : every malicious step intercepted, data never left the server")
    print()


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print(bold("╔══════════════════════════════════════════════════════════════╗"))
    print(bold("║   DOOMSDAY CORP — VEIL Security Demo                        ║"))
    print(bold("║   Before / After — same attack, two outcomes                ║"))
    print(bold("╚══════════════════════════════════════════════════════════════╝"))
    print(dim(f"  Server : {HOST}"))

    check_connection()
    phase_vulnerable()
    phase_protected()
    summary()
