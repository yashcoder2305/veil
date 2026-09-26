# VEIL — Final Engineering Plan
**Verifiable Execution Isolation Layer | Team Doomsday**

> THE AGENT REQUESTS. VEIL VERIFIES. THE POLICY DECIDES. THE GATEWAY ENFORCES. THE AUDIT REMEMBERS.

---

## What Is Already Built (Do Not Rebuild)

The following are **complete, tested, and working**. Do not touch unless fixing a bug.

| Module | Owner | Status |
|---|---|---|
| `veil/models/` — Action, Decision, all result types | Both | ✅ Done |
| `veil/gateway/` — Interceptor, Normalizer, Executor | Durga | ✅ Done |
| `veil/security/` — Classifier, Capabilities, Policy | Durga | ✅ Done |
| `veil/security/` — Trajectory, Risk, Injection | Yash | ✅ Done |
| `veil/agents/` — Counter, Judge, Decision, Revocation | Yash | ✅ Done |
| `veil/memory/` — Audit, Threats, Feedback | Both | ✅ Done |
| `veil/pipeline.py` — Full pipeline orchestration | Both | ✅ Done |
| `simulator/client/` — Resources, Tools, Agents, Scenarios, Runner | Durga | ✅ Done |
| `simulator/attacker/` — Attack scenarios | Yash | ✅ Done |
| `dashboard/app.py` — All 5 pages | Yash | ✅ Done |
| Unit + integration tests (71+ passing) | Both | ✅ Done |

---

## What Is Missing (The Real Work Left)

```
FastAPI Gateway API     ← Durga     P0 — blocks everything else
Real LLM Agent          ← Yash      P1 — needed for Before/After demo
Dashboard Attack Lab    ← Yash      P2 — needs API first
Docker + Compose        ← Both      P3 — last, after everything works
```

---

## Architecture — Final Target

```
Browser / Judge
      ↓
Streamlit Dashboard  (dashboard/app.py)
      ↓  POST /api/v1/attacks/run  or  /api/v1/execute
FastAPI Gateway  (api/main.py)            ← MISSING
      ↓
VEILPipeline.run()  (veil/pipeline.py)    ← EXISTS
      ↓
[Capability → Policy → Trajectory → Risk → Injection → Counter → Judge → Decision]
      ↓
Executor → Audit → Response
      ↓
Dashboard renders live result
```

---

## Ownership Split

### DURGA owns the trusted boundary
`veil/gateway/`, `veil/security/classifier+capabilities+policy`, `veil/memory/audit`, `simulator/client/`, **`api/`**, **`Dockerfile`**, **`docker-compose.yml`**

### YASH owns the security intelligence and UI
`veil/security/trajectory+risk+injection`, `veil/agents/`, `veil/memory/threats+feedback`, `simulator/attacker/`, **`dashboard/`** (Attack Lab + Live Agent), **`simulator/client/live_agent.py`**

### Shared
`veil/models/`, `veil/pipeline.py`, `veil/config.py`, integration tests, final demo

---

## Sub-Tasks

---

### Sub-Task A — FastAPI Gateway
**Owner:** Durga
**Status:** [ ] pending
**Priority:** P0 — blocks Attack Lab and Live Agent demo

**Intent**
Expose `VEILPipeline.run()` through a real HTTP API so the dashboard, live agent, and demo can submit requests without importing Python directly. This is what makes VEIL a deployable runtime gateway rather than a library.

**Expected Outcomes**
- `api/main.py` runs with `uvicorn api.main:app --port 8000`
- `GET /api/v1/health` returns component status (pipeline, audit, capabilities)
- `POST /api/v1/execute` accepts a raw tool-call JSON body, runs the full pipeline, returns `DecisionResult` + execution status + audit record ID
- `POST /api/v1/attacks/run` accepts `{"scenario": "p0_attack"}`, runs the named simulator scenario through the pipeline, returns all step results
- `GET /api/v1/events` returns recent audit records (last N, filterable by session/decision)
- `GET /api/v1/agents` returns all registered agent profiles and their capability grants
- `GET /api/v1/capabilities` returns the full capability registry
- A legitimate request → ALLOW → tool executes → response contains tool output
- A malicious request → BLOCK → tool does not execute → response contains block reason
- All endpoints return structured JSON — no plain text errors

**Todo List**
- [ ] Create `api/__init__.py`
- [ ] Create `api/main.py` — FastAPI app with CORS, lifespan startup (instantiate VEILPipeline singleton)
- [ ] Implement `GET /api/v1/health` — ping each component, return green/red per component
- [ ] Implement `POST /api/v1/execute` — accept raw dict, call `pipeline.run()`, return structured response
- [ ] Implement `POST /api/v1/attacks/run` — load named scenario from `SCENARIOS` registry, run each action through pipeline, return list of step results
- [ ] Implement `GET /api/v1/events` — read from `AuditEngine.query()`, support `?session_id=` and `?limit=` params
- [ ] Implement `GET /api/v1/agents` — return `CapabilityManager.all_profiles()`
- [ ] Implement `GET /api/v1/capabilities` — same source, different shape
- [ ] Add request/response Pydantic models for all endpoints
- [ ] Test all endpoints manually with `curl` or the FastAPI `/docs` UI
- [ ] Update `README.md` — add API startup command

**Relevant Context**
- `veil/pipeline.py` — `VEILPipeline.run(raw_payload) -> PipelineResult` — this is what every endpoint calls
- `simulator/client/scenarios.py` — `SCENARIOS` dict maps name → list of Actions
- `veil/memory/audit.py` — `AuditEngine.query(session_id)` for the events endpoint
- `veil/security/capabilities.py` — `CapabilityManager.all_profiles()` for agents endpoint
- Run with: `uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload`

---

### Sub-Task B — Real LLM Agent
**Owner:** Yash
**Priority:** P1
**Status:** [ ] pending

**Intent**
Replace hand-crafted Action dicts with a real Groq-driven agent that receives a user instruction, reasons about which tool to call, and submits the tool call to the VEIL API. This enables the "Before/After VEIL" demonstration — the same malicious input that succeeds without VEIL is blocked by VEIL.

**Expected Outcomes**
- `simulator/client/live_agent.py` — `LiveAgent` class that accepts a natural language instruction, uses Groq to decide on a tool call, POSTs to `POST /api/v1/execute`, and returns the pipeline result
- The agent can be driven with benign and malicious instructions
- Malicious instruction → agent proposes dangerous tool call → VEIL blocks it → tool never executes
- Benign instruction → agent proposes legitimate tool call → VEIL allows → tool executes
- The Before/After demo works: run the same malicious instruction with `VEIL_ENABLED=false` (direct tool call, no gateway) and with `VEIL_ENABLED=true` (via gateway)

**Todo List**
- [ ] Create `simulator/client/live_agent.py` — `LiveAgent(agent_id, session_id, api_base_url)`
- [ ] Implement `LiveAgent.run(instruction: str) -> dict` — Groq call to select tool + params from instruction, POST to `/api/v1/execute`, return result
- [ ] Define a compact system prompt: agent identity, available tools, output format (JSON tool call)
- [ ] Implement `LiveAgent.run_without_veil(instruction: str) -> dict` — calls tool stub directly, bypassing the gateway (for Before/After demo)
- [ ] Create `simulator/client/demo.py` — CLI script: `python simulator/client/demo.py --mode before` vs `--mode after` with the same malicious instruction
- [ ] Test with benign instruction → ALLOW confirmed
- [ ] Test with injected instruction → BLOCK confirmed

**Relevant Context**
- `api/main.py` must be running before this can be tested — depends on Sub-Task A
- `simulator/client/tools.py` — `dispatch(action)` — the tool stubs the agent would call directly in Before mode
- `veil/config.py` — `settings.groq_api_key`, `settings.groq_model_id` — reuse for agent LLM calls
- Working model: `openai/gpt-oss-20b` (confirmed working on current API key)
- The agent must never receive raw PII back from VEIL — only the decision result

---

### Sub-Task C — Dashboard Attack Lab + Live Updates
**Owner:** Yash
**Priority:** P2
**Status:** [ ] pending

**Intent**
Add two things to the existing dashboard:
1. An **Attack Lab page** with buttons that trigger real pipeline calls via the API — no prerecorded results.
2. **Live auto-refresh** on the Live Activity page so audit events appear in real time during a demo.

**Expected Outcomes**
- New "Attack Lab" page in the sidebar
- Six attack buttons: Prompt Injection, Data Exfiltration, Privilege Abuse, PII Write, Multi-Step Chain, Legitimate Request
- Each button calls `POST /api/v1/attacks/run` with the corresponding scenario name
- Result is displayed inline: step-by-step decisions with color-coded badges
- "Before VEIL / After VEIL" toggle that shows the same attack with and without the gateway
- Live Activity page auto-refreshes every 3 seconds during demo mode
- Dashboard reads API URL from environment variable `VEIL_API_URL` (default: `http://localhost:8000`)

**Todo List**
- [ ] Add `VEIL_API_URL` to `veil/config.py` and `.env.example`
- [ ] Add `httpx` calls from dashboard to API (already in `requirements.txt`)
- [ ] Add "Attack Lab" to sidebar navigation in `dashboard/app.py`
- [ ] Implement `page_attack_lab()` — six scenario buttons, results rendered inline per step
- [ ] Implement Before/After toggle — calls `/api/v1/attacks/run` for After, calls simulator directly for Before
- [ ] Update Live Activity page — add 3-second auto-refresh toggle
- [ ] Add component health indicators to Overview page using `GET /api/v1/health`

**Relevant Context**
- `dashboard/app.py` — existing page structure; add Attack Lab as a new route
- `api/main.py` — `POST /api/v1/attacks/run` and `GET /api/v1/health` (Sub-Task A)
- `simulator/client/scenarios.py` — `SCENARIOS` dict — use same names as API
- `httpx` is already in `requirements.txt`

---

### Sub-Task D — Docker + Compose
**Owner:** Durga (Dockerfile) + Yash (verify dashboard service)
**Priority:** P3
**Status:** [ ] pending

**Intent**
Package the entire system into a single `docker compose up` command so the demo can run anywhere without Python environment setup. One command starts the API, dashboard, and data volume.

**Expected Outcomes**
- `Dockerfile` builds the full project
- `docker-compose.yml` defines two services: `veil-api` (FastAPI on port 8000) and `veil-dashboard` (Streamlit on port 8501)
- Both services share a `data/` volume for the audit JSONL file
- `docker compose up` starts both; demo is accessible at `localhost:8501`
- Environment variables are passed via `.env` file
- `GET /api/v1/health` returns green for all components

**Todo List**
- [ ] Create `Dockerfile` — Python 3.11 slim, install requirements, copy source
- [ ] Create `docker-compose.yml` — `veil-api` and `veil-dashboard` services, shared `data/` volume, `.env` file reference
- [ ] Add `data/` directory creation to container startup
- [ ] Verify `docker compose up` starts cleanly
- [ ] Test `POST /api/v1/attacks/run` from dashboard container to API container
- [ ] Add Docker instructions to `README.md`

**Relevant Context**
- API runs: `uvicorn api.main:app --host 0.0.0.0 --port 8000`
- Dashboard runs: `streamlit run dashboard/app.py --server.port 8501`
- API URL inside Docker: `http://veil-api:8000` (service name, not localhost)
- Set `VEIL_API_URL=http://veil-api:8000` in docker-compose environment

---

## VEIL Suggestions (Engineering Improvements)

These are not required for the demo but add correctness or demo impact. Each is small.

### 1. P0 Attack Should End in REVOKE, Not Just BLOCK

Currently the P0 chain produces two BLOCKs. The demo story is stronger if Step 3 (the exfiltration attempt) triggers a **REVOKE** of `http.request` capability for the session, so that any further attempt is also blocked with `is_revoked=True`.

To achieve this: in `veil/agents/decision.py`, add a rule — when `POLICY_EXTERNAL_HTTP_FROM_NON_RESEARCH` + `POLICY_PII_TO_EXTERNAL` both fire, escalate to `REVOKE` instead of `BLOCK`. This makes the timeline show: WARN → ALLOW → REVOKE — a much clearer attack story for judges.

**Owner:** Yash (decision.py)

### 2. Health Endpoint Should Actually Test Each Component

`GET /api/v1/health` should not just return `{"status": "ok"}`. It should instantiate and ping each component:
- Capability registry loaded → green
- Audit file writable → green
- Groq API key present (not necessarily valid) → green/yellow
- Pipeline instantiation succeeds → green

This gives judges a live "component health" view matching the dashboard design.

**Owner:** Durga (api/main.py)

### 3. Session ID Per Demo Run

Currently all P0 runs use the hardcoded `session_id="sess-p0-001"`. In the Attack Lab, each button click should generate a fresh `session_id` (UUID). Otherwise the trajectory engine sees accumulated history across runs and produces misleading results.

Fix: in `api/main.py` `attacks/run` endpoint, generate a fresh `session_id` per request and inject it into each action before running.

**Owner:** Durga (api/main.py)

### 4. Dashboard Should Show Judge Reasoning

The Threat Investigation page shows policy violations and risk level but not the judge's reasoning text. The audit record already stores `reason` which contains the full judge verdict (e.g. *"The agent attempts to read PII and exfiltrate to attacker-controlled endpoint..."*). Surface this in the expander — it's the most compelling part of the demo.

The field is already in `AuditRecord.reason`. Just display it prominently.

**Owner:** Yash (dashboard/app.py)

### 5. Before/After Must Use The Same Session

For the Before/After demo to be convincing, the malicious instruction must be identical in both modes. The difference must be only whether the gateway is in the path. Document this explicitly in `demo.py` so it's reproducible under pressure.

**Owner:** Yash (simulator/client/demo.py)

---

## Integration Checkpoints

Before Sub-Task B starts: Sub-Task A must be running. Test with `curl http://localhost:8000/api/v1/health`.

Before Sub-Task C starts: Sub-Task A must have `POST /api/v1/attacks/run` working.

Before Docker: Sub-Tasks A, B, C must all be working locally.

---

## Final Demo Sequence (For Judges)

```
1. Open dashboard → Overview shows VEIL ACTIVE
2. Capabilities page → show agent permission matrix
3. Run "Legitimate Request" in Attack Lab → ALLOW → tool executed → audit event appears
4. Run "P0 Attack" in Attack Lab → step by step:
      Step 1: database.read → BLOCK (AI judge: "data exfiltration attempt")
      Step 2: file.read → ALLOW (cover action passes)
      Step 3: http.request → REVOKE (exfiltration blocked, capability revoked)
5. Attack Timeline → show full session chain with judge reasoning
6. Before/After demo → same attack, without VEIL it succeeds, with VEIL it's contained
7. Component Health → all green
```

---

## What NOT to Build

Do not spend time on:
- Fine-tuning models
- Kubernetes
- Real external network calls
- Blockchain audit logs
- Fancy UI animations not tied to real events
- Extra attack types beyond what's already in scenarios.py
- Automatic model retraining
- Features that bypass the deterministic gateway

---

## Definition of Done

- [ ] `POST /api/v1/execute` processes a real request end-to-end
- [ ] A blocked tool genuinely does not execute
- [ ] `POST /api/v1/attacks/run` runs named scenarios through the live pipeline
- [ ] Real LLM agent submits tool requests to the API
- [ ] Dashboard Attack Lab triggers real pipeline calls
- [ ] Before/After demo works with the same malicious input
- [ ] REVOKE decision appears in at least one scenario
- [ ] Judge reasoning is visible in the dashboard
- [ ] `docker compose up` starts the full system
- [ ] No secrets committed to git
- [ ] `GET /api/v1/health` shows all components green
- [ ] README explains setup, architecture, and demo sequence

---

## File Ownership Reference

```
DURGA
  api/main.py                         ← NEW — P0
  api/__init__.py                     ← NEW
  Dockerfile                          ← NEW
  docker-compose.yml                  ← NEW
  veil/gateway/                       ← exists
  veil/security/classifier+cap+policy ← exists
  veil/memory/audit.py                ← exists
  simulator/client/                   ← exists

YASH
  simulator/client/live_agent.py      ← NEW — P1
  simulator/client/demo.py            ← NEW — P1
  dashboard/app.py  (Attack Lab)      ← extend existing — P2
  veil/agents/decision.py  (REVOKE)   ← small fix — suggestion 1
  veil/security/trajectory+risk+inj   ← exists
  veil/agents/                        ← exists
  simulator/attacker/                 ← exists

BOTH
  veil/models/                        ← stable, do not change
  veil/pipeline.py                    ← stable
  veil/config.py                      ← add VEIL_API_URL
  tests/                              ← add integration tests when API is done
  README.md                           ← update with API + Docker instructions
```

---

## Core Principle

The deterministic layer (capabilities, policy, classification) is the hard security boundary. It cannot be bypassed by an LLM. VEIL-Counter and VEIL-Judge are adversarial analysts — they raise the quality of decisions for ambiguous cases. The gateway enforces. The LLM advises.
