# VEIL Engineering Plan
**Verifiable Execution Isolation Layer — IBM Bob 2.0 Hackathon**

## Overview

VEIL is a runtime security boundary that intercepts, evaluates, and enforces AI agent actions before they reach target tools, APIs, databases, file systems, or network capabilities. The LLM is advisory; VEIL controls the door.

**Demo story (P0):** Prompt injection → PII read → transform → external HTTP transfer → VEIL blocks + revokes network capability + full audit trail visible in Streamlit dashboard.

**Two-person team:**
- **Durga** — Gateway & Deterministic Layer
- **Yash** — Intelligence & Agentic Layer

**LLM backend:** IBM watsonx.ai (Granite or Llama)
**Dashboard:** Streamlit
**Audit/threat persistence:** JSON file append
**Shared models:** `veil/models/` (neutral package imported by both domains)

---

## Architecture

```
AI Agent
    ↓
Action Interceptor        (veil/gateway/interceptor.py)
    ↓
Action Normalizer         (veil/gateway/normalizer.py)
    ↓
Capability + Policy       (veil/security/capabilities.py + policy.py)
    ↓
Risk + Trajectory         (veil/security/risk.py + trajectory.py)
    ↓
Counter-Agent / Judge     (veil/agents/counter.py + judge.py)   ← only when suspicious
    ↓
Decision Engine           (veil/agents/decision.py)
    ↓
ALLOW / WARN / REQUIRE_APPROVAL / BLOCK / REVOKE
    ↓
Executor or Block         (veil/gateway/executor.py)
    ↓
Audit Event               (veil/memory/audit.py)
```

---

## Sub-Tasks

---

### Sub-Task 1 — Shared Models Package
**Owner:** Both (must be completed first — unblocks all other sub-tasks)
**Status:** [ ] pending

**Intent**
Define the canonical `Action` schema and all shared result/decision types in a neutral package (`veil/models/`) that both Durga's and Yash's modules import from. This is the integration contract — no other work can begin until these are stable.

**Expected Outcomes**
- `veil/models/__init__.py` exports `Action`, `DecisionResult`, `PolicyResult`, `RiskResult`, `CapabilityResult`.
- `veil/models/action.py` contains the `Action` dataclass/Pydantic model with all fields from Section 3 of the spec.
- `veil/models/decisions.py` contains the `Decision` enum (`ALLOW`, `WARN`, `REQUIRE_APPROVAL`, `BLOCK`, `REVOKE`) and `DecisionResult`.
- `veil/models/results.py` contains `PolicyResult`, `RiskResult`, `CapabilityResult`, `InjectionResult`.
- All fields have types and docstrings. No field is optional unless explicitly justified.
- `requirements.txt` is created with `pydantic`, `ibm-watsonx-ai`, `streamlit`, `fastapi`, `uvicorn`.

**Todo List**
- [ ] Create `veil/models/action.py` — `Action` Pydantic model with fields: `agent_id`, `session_id`, `timestamp`, `tool`, `operation`, `resource`, `destination`, `data_classification`, `requested_capability`, `purpose`, `provenance`, `metadata`.
- [ ] Create `veil/models/decisions.py` — `Decision` enum and `DecisionResult(decision, reason, triggered_rules, confidence, requires_human_review)`.
- [ ] Create `veil/models/results.py` — `PolicyResult`, `RiskResult`, `CapabilityResult`, `InjectionResult` with clear fields.
- [ ] Create `veil/models/__init__.py` — re-export all public types.
- [ ] Create `requirements.txt` at repo root.
- [ ] Create `veil/__init__.py` (empty, marks package root).

**Relevant Context**
- Spec Section 3: Standard Action Model fields.
- Spec Section 12: P0 — shared agreement on Action fields is gating work.
- No existing code to reference — greenfield.

---

### Sub-Task 2 — Project Scaffold & Configuration
**Owner:** Durga
**Status:** [ ] pending

**Intent**
Stand up the full directory skeleton, a working Python environment, and a base configuration file so both developers can clone, install, and run code immediately without environment setup friction.

**Expected Outcomes**
- Full directory tree created (all `__init__.py` files in place).
- `config/settings.py` (or `veil/config.py`) holds environment-driven config: watsonx API key, model ID, audit file path, threat memory file path.
- `python -m veil` (or a simple entry-point script) runs without import errors.
- `.env.example` documents required environment variables.
- `README.md` updated with setup instructions.

**Todo List**
- [ ] Create all package directories with `__init__.py`: `veil/gateway/`, `veil/security/`, `veil/agents/`, `veil/memory/`, `veil/models/`, `simulator/client/`, `simulator/attacker/`, `dashboard/`.
- [ ] Create `veil/config.py` — reads `WATSONX_API_KEY`, `WATSONX_PROJECT_ID`, `WATSONX_MODEL_ID`, `AUDIT_FILE_PATH`, `THREAT_MEMORY_PATH` from environment with sensible defaults.
- [ ] Create `.env.example` documenting all required variables.
- [ ] Update `README.md` with: project description, setup steps (`pip install -r requirements.txt`), how to run the simulator and dashboard.

**Relevant Context**
- All subsequent modules import from `veil.config` for runtime settings.
- watsonx.ai credentials will be needed by Yash's agents — define the config shape here so both sides agree.

---

### Sub-Task 3 — Gateway Layer (Durga)
**Owner:** Durga
**Status:** [ ] pending

**Intent**
Implement the three gateway modules — Interceptor, Normalizer, Executor — that form the entry and exit of the VEIL pipeline. No security logic lives here; this layer only routes and enforces the "no execution without a decision" rule.

**Expected Outcomes**
- `veil/gateway/interceptor.py` — `ActionInterceptor.intercept(raw_payload) -> Action` receives a raw tool-call dict, calls the normalizer, and forwards to the pipeline.
- `veil/gateway/normalizer.py` — `ActionNormalizer.normalize(raw_payload) -> Action` converts tool-call dicts (from any agent framework) into the shared `Action` model.
- `veil/gateway/executor.py` — `ActionExecutor.execute(action, decision_result) -> ExecutionResult` only proceeds when `decision_result.decision == Decision.ALLOW`; raises or returns an error for all other decisions.
- Unit tests for each module in `tests/gateway/`.

**Todo List**
- [ ] Implement `ActionNormalizer.normalize()` — map common tool-call dict keys to `Action` fields; handle missing optional fields gracefully.
- [ ] Implement `ActionInterceptor.intercept()` — validate raw payload structure, call normalizer, return `Action`.
- [ ] Implement `ActionExecutor.execute()` — enforce decision gate; for `ALLOW` delegate to the actual tool call stub; for everything else return a blocked result without executing.
- [ ] Write `tests/gateway/test_normalizer.py`, `test_interceptor.py`, `test_executor.py`.

**Relevant Context**
- `veil/models/action.py` — `Action` model (Sub-Task 1).
- `veil/models/decisions.py` — `Decision` enum, `DecisionResult` (Sub-Task 1).
- Spec Section 4.1–4.3.
- Rule: gateway modules must not import from `veil/agents/` or `veil/security/trajectory.py`.

---

### Sub-Task 4 — Deterministic Security Layer (Durga)
**Owner:** Durga
**Status:** [ ] pending

**Intent**
Implement the three deterministic security modules — Capability Manager, Policy Engine, Data Classifier — that form the first and cheapest security gate. These never call an LLM.

**Expected Outcomes**
- `veil/security/capabilities.py` — `CapabilityManager.check(action) -> CapabilityResult` returns allowed/denied with reason based on per-agent capability rules.
- `veil/security/policy.py` — `PolicyEngine.evaluate(action, capability_result) -> PolicyResult` enforces hard rules: forbidden operations, sensitive data to untrusted destinations, etc.
- `veil/security/classifier.py` — `DataClassifier.classify(resource, data_hint) -> DataClassification` returns one of `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `PII`, `FINANCIAL`, `SECRET`, `CREDENTIAL`.
- SupportAgent, ResearchAgent, FinanceAgent capability rules are defined and tested.
- Unit tests in `tests/security/`.

**Todo List**
- [ ] Define agent capability registry in `capabilities.py` — per-agent allowed tools and resources, e.g. `SupportAgent` may `database.read` on `customer_db` but not `database.write` on `payment_records`.
- [ ] Implement `CapabilityManager.check(action) -> CapabilityResult`.
- [ ] Implement `PolicyEngine.evaluate()` — rules for: unauthorized capability, forbidden operation (e.g. `shell.execute` for non-admin), sensitive data to untrusted external destination.
- [ ] Implement `DataClassifier.classify()` — resource name and data hint → classification label.
- [ ] Wire classifier output into the `Action` at normalization time or at policy evaluation time.
- [ ] Write `tests/security/test_capabilities.py`, `test_policy.py`, `test_classifier.py`.

**Relevant Context**
- `veil/models/results.py` — `CapabilityResult`, `PolicyResult` (Sub-Task 1).
- Spec Section 4.4–4.6.
- Simulator resources and their classifications are defined in Sub-Task 6.

---

### Sub-Task 5 — Intelligence & Agentic Layer (Yash)
**Owner:** Yash
**Status:** [ ] pending

**Intent**
Implement the full intelligence layer: Trajectory Engine, Risk Engine, Injection Detector, Counter-Agent, Judge Agent, Decision Engine, and Capability Revocation. LLM calls go here and only here. The Decision Engine's output is the advisory signal that feeds the final deterministic enforcement.

**Expected Outcomes**
- `veil/security/trajectory.py` — `TrajectoryEngine.record(action)` and `TrajectoryEngine.analyze(session_id) -> TrajectoryAnalysis` detect suspicious action chains (e.g. READ PII → TRANSFORM → EXTERNAL TRANSFER).
- `veil/security/risk.py` — `RiskEngine.score(action, capability_result, policy_result, trajectory_analysis) -> RiskResult` returns a risk level and contributing factors.
- `veil/security/injection.py` — `InjectionDetector.detect(action) -> InjectionResult` flags direct and indirect prompt-injection signals.
- `veil/agents/counter.py` — `CounterAgent.analyze(action, context) -> CounterAgentFinding` uses watsonx to construct plausible abuse scenarios. Called only for high-risk actions.
- `veil/agents/judge.py` — `JudgeAgent.review(action, counter_finding, context) -> JudgeVerdict` reviews counter-agent findings against agent goal and permissions.
- `veil/agents/decision.py` — `DecisionEngine.decide(risk_result, policy_result, capability_result, judge_verdict) -> DecisionResult` combines all signals into a final `Decision` enum value. Deterministic logic — not an LLM.
- `veil/agents/revocation.py` — `RevocationEngine.revoke(agent_id, capability) -> RevocationRecord` disables a specific capability for the session.
- Unit/integration tests in `tests/intelligence/`.

**Todo List**
- [ ] Implement `TrajectoryEngine` — in-memory session keyed store of `Action` sequences; pattern matcher for known dangerous chains.
- [ ] Implement `RiskEngine.score()` — weighted combination of capability risk, data sensitivity, destination risk, policy violations, trajectory anomaly flag.
- [ ] Implement `InjectionDetector.detect()` — heuristic + pattern matching for injection signals in `action.purpose`, `action.metadata`, and tool output data.
- [ ] Implement `CounterAgent.analyze()` — watsonx.ai call with compact prompt: action metadata + recent trajectory; parse structured finding from response.
- [ ] Implement `JudgeAgent.review()` — watsonx.ai call that reviews counter finding against declared agent goal + permissions; returns verdict with confidence.
- [ ] Implement `DecisionEngine.decide()` — pure logic combining all result objects into a `Decision` enum; LLM findings are inputs but cannot override a deterministic BLOCK.
- [ ] Implement `RevocationEngine.revoke()` — stores revoked capabilities per agent/session; `CapabilityManager` must query this store on every check.
- [ ] Write tests in `tests/intelligence/`.

**Relevant Context**
- `veil/models/` — all shared types (Sub-Task 1).
- `veil/config.py` — watsonx credentials (Sub-Task 2).
- Spec Sections 5.1–5.9.
- Counter-Agent and Judge must receive compact metadata only — no raw customer data.
- `RevocationEngine` state must be consulted by `CapabilityManager` (Sub-Task 4) — coordinate the interface.

---

### Sub-Task 6 — Client Simulator — DOOMSDAY CORP (Durga)
**Owner:** Durga
**Status:** [ ] pending

**Intent**
Build a fully deterministic simulator for DOOMSDAY CORP so security behavior is reproducible. The simulator provides fake resources, tool stubs, and test agents that feed real `Action` objects into the VEIL pipeline.

**Expected Outcomes**
- `simulator/client/resources.py` — deterministic data store for `customer_db`, `employee_db`, `internal_docs`, `public_docs`, `payment_records`, `secrets` with correct classification labels.
- `simulator/client/tools.py` — stub implementations of `database.read`, `database.write`, `file.read`, `file.write`, `http.request`, `email.read`, `email.send`, `shell.execute` that return fixed fake data.
- `simulator/client/agents.py` — `ResearchAgent`, `SupportAgent`, `FinanceAgent` each with declared capabilities and a `run_scenario(scenario_name)` method.
- `simulator/client/scenarios.py` — named scenario definitions including the P0 attack chain.
- The simulator can be run standalone to feed actions into VEIL and print results.

**Todo List**
- [ ] Define `RESOURCES` registry — resource name → classification, sample data rows.
- [ ] Implement tool stubs — each returns deterministic fake data; `http.request` to an external destination always returns a mock HTTP 200.
- [ ] Define agent profiles — capability grants and declared goals per agent.
- [ ] Implement `SupportAgent` scenario: legitimate PII read → allowed.
- [ ] Implement P0 attack scenario: injected instruction in `purpose` field → PII read → transform → external HTTP POST → VEIL should block and revoke.
- [ ] Write `simulator/client/run.py` as entry point to execute a named scenario.

**Relevant Context**
- `veil/models/action.py` — `Action` fields and classification enum (Sub-Task 1).
- `veil/security/classifier.py` — resource classification (Sub-Task 4).
- Spec Section 6.

---

### Sub-Task 7 — Attacker Simulator (Yash)
**Owner:** Yash
**Status:** [ ] pending

**Intent**
Implement controlled attack scenario generators that produce sequences of `Action` objects representing known attack patterns. These feed into VEIL to validate detection and blocking.

**Expected Outcomes**
- `simulator/attacker/scenarios.py` — at minimum: prompt injection, PII exfiltration, privilege abuse, dangerous tool execution, multi-step attack chain.
- Each scenario returns a list of `Action` objects that can be fed to the pipeline.
- The P0 chain is a named, runnable scenario.

**Todo List**
- [ ] Implement `PromptInjectionScenario` — crafts `Action` with injection signal in `purpose`/`metadata`.
- [ ] Implement `PiiExfiltrationChain` — READ PII → TRANSFORM → EXTERNAL HTTP POST.
- [ ] Implement `PrivilegeAbuseScenario` — agent requests capability it does not hold.
- [ ] Implement `MultiStepChain` — combines injection + PII access + exfiltration in sequence.
- [ ] Write `simulator/attacker/run.py` as an entry point.

**Relevant Context**
- `veil/models/action.py` (Sub-Task 1).
- Spec Section 7.
- Implement after Sub-Task 6 (client simulator) is done.

---

### Sub-Task 8 — Audit Engine (Durga)
**Owner:** Durga
**Status:** [ ] pending

**Intent**
Implement synchronous, non-optional audit event logging that writes every security decision to a JSON file. Every decision path must call the audit engine before returning.

**Expected Outcomes**
- `veil/memory/audit.py` — `AuditEngine.log(action, decision_result)` appends a JSON line to the audit file.
- Audit record includes: `action_id`, `agent_id`, `session_id`, `timestamp`, `tool`, `operation`, `resource`, `policy_result`, `risk_level`, `decision`, `reason`, `triggered_rules`.
- `AuditEngine.query(session_id)` returns all events for a session (for dashboard use).
- Thread-safe append (file lock or atomic write).

**Todo List**
- [ ] Define `AuditRecord` Pydantic model.
- [ ] Implement `AuditEngine.log()` — serialize to JSON line, append to configured file path.
- [ ] Implement `AuditEngine.query(session_id)` — read and filter audit file.
- [ ] Add file locking for concurrent write safety.
- [ ] Write `tests/memory/test_audit.py`.

**Relevant Context**
- `veil/config.py` — `AUDIT_FILE_PATH` (Sub-Task 2).
- `veil/models/decisions.py` — `DecisionResult` (Sub-Task 1).
- Spec Section 4.7.

---

### Sub-Task 9 — Threat Memory & Feedback Engine (Yash)
**Owner:** Yash
**Status:** [ ] pending

**Intent**
Implement sanitized threat memory storage and a feedback engine that allows validated security observations to be written back. No raw customer data is stored.

**Expected Outcomes**
- `veil/memory/threats.py` — `ThreatMemory.record(pattern)` appends sanitized attack pattern; `ThreatMemory.query(action) -> list[ThreatPattern]` returns matching patterns.
- `veil/memory/feedback.py` — `FeedbackEngine.submit(feedback)` writes validated feedback to threat memory or policy knowledge; no automatic LLM retraining.
- Both backed by JSON file append.

**Todo List**
- [ ] Define `ThreatPattern` model — pattern type, indicators, severity, first_seen, last_seen (no raw PII).
- [ ] Implement `ThreatMemory.record()` and `ThreatMemory.query()`.
- [ ] Define `FeedbackRecord` model.
- [ ] Implement `FeedbackEngine.submit()` — validates, sanitizes, appends to threat memory file.
- [ ] Write `tests/memory/test_threats.py`.

**Relevant Context**
- `veil/config.py` — `THREAT_MEMORY_PATH` (Sub-Task 2).
- Spec Sections 5.8–5.9.

---

### Sub-Task 10 — Pipeline Integration
**Owner:** Both
**Status:** [ ] pending

**Intent**
Wire all modules into the complete enforcement pipeline as described in Section 11 of the spec. Validate the first integration contract end-to-end.

**Expected Outcomes**
- `veil/pipeline.py` — `VEILPipeline.run(raw_payload) -> DecisionResult` orchestrates the full chain: normalize → capability check → policy check → trajectory record → risk score → injection detect → (conditional) counter-agent → judge → decision → executor → audit.
- The P0 attack chain runs through the pipeline and is blocked with a `REVOKE` decision visible in the audit file.
- A legitimate `SupportAgent` action passes through and is audited as `ALLOW`.

**Todo List**
- [ ] Implement `VEILPipeline.run()` composing all modules in order.
- [ ] Add conditional logic: only invoke Counter-Agent/Judge when `risk_result.level >= HIGH` or `injection_result.detected`.
- [ ] Verify `RevocationEngine` state is checked by `CapabilityManager` on subsequent calls in the same session.
- [ ] Run the P0 scenario end-to-end; confirm audit file shows BLOCK + REVOKE events.
- [ ] Run a legitimate scenario; confirm audit file shows ALLOW events.
- [ ] Write `tests/test_pipeline.py` with both scenarios.

**Relevant Context**
- All sub-tasks 1–9 must be complete before this sub-task begins.
- Spec Section 11: First Integration Contract.
- Spec Section 14: Definition of Done.

---

### Sub-Task 11 — Streamlit Dashboard
**Owner:** Yash
**Status:** [ ] pending

**Intent**
Build the Streamlit dashboard that reads the audit JSON file and visualizes the security engine's activity. This is evidence for judges, not the product itself.

**Expected Outcomes**
- `dashboard/app.py` — Streamlit app with pages: Overview, Live Activity, Attack Timeline, Threat Investigation, Capabilities/Policy View.
- Overview: protected status indicator, total actions, threats detected, blocked actions, warnings, revocations.
- Live Activity: auto-refreshing table of recent audit events (agent, action, risk, decision, timestamp).
- Attack Timeline: chronological action chain for a selected session.
- Threat Investigation: trajectory view, threat category, counter-agent result, judge result, final decision.
- Capabilities/Policy View: per-agent capability grants and denials.
- Dashboard reads from the audit JSON file (`AuditEngine.query()`).

**Todo List**
- [ ] Implement `dashboard/app.py` with sidebar navigation.
- [ ] Overview page — aggregate stats from audit file.
- [ ] Live Activity page — recent events table with auto-refresh (`st.experimental_rerun` or `st.rerun`).
- [ ] Attack Timeline page — session selector, chronological event chain.
- [ ] Threat Investigation page — detailed view with counter-agent and judge findings.
- [ ] Capabilities/Policy page — static view of agent capability registry.
- [ ] Test dashboard loads without error against a sample audit file.

**Relevant Context**
- `veil/memory/audit.py` — `AuditEngine.query()` (Sub-Task 8).
- `veil/security/capabilities.py` — agent capability registry (Sub-Task 4).
- Spec Section 8.

---

## Dependency Order

```
Sub-Task 1 (Models)
    ↓
Sub-Task 2 (Scaffold)
    ↓
Sub-Tasks 3, 4, 5 (Gateway, Security, Intelligence — parallel, Durga/Yash)
    ↓
Sub-Tasks 6, 7, 8, 9 (Simulators, Audit, Threats — parallel)
    ↓
Sub-Task 10 (Pipeline Integration)
    ↓
Sub-Task 11 (Dashboard)
```

---

## Integration Contract (First Merge Gate)

Before either branch merges to `main`, the following must pass:

1. A raw tool-call dict enters `VEILPipeline.run()`.
2. It is normalized into an `Action`.
3. Capability and policy checks run deterministically.
4. A `DecisionResult` is returned.
5. The executor is gated on `ALLOW` only.
6. An audit event is written to the JSON file.
7. Yash's `TrajectoryEngine` and `RiskEngine` can consume the same `Action` object without modification.

---

## Definition of Done (Core)

- [ ] A proposed `Action` can be normalized and validated.
- [ ] An agent's capabilities can be checked deterministically.
- [ ] A policy can return `ALLOW` or `BLOCK` for basic cases.
- [ ] A blocked action never reaches the executor.
- [ ] Every decision creates an audit event.
- [ ] Trajectory/risk modules consume the same `Action` object.
- [ ] High-risk actions trigger agentic analysis without making the LLM the final enforcement authority.
- [ ] The system demonstrates at least one multi-step attack being blocked.

---

## Core Engineering Principle

> "The LLM can be compromised. The prompt can be malicious. VEIL still controls the door."
