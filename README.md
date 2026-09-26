# VEIL — Verifiable Execution Isolation Layer

> "The LLM can be compromised. The prompt can be malicious. VEIL still controls the door."

Runtime security boundary for AI agents — IBM Bob 2.0 Hackathon | **Team Doomsday**

---

## What VEIL Does

VEIL intercepts every tool call an AI agent attempts to make, evaluates it through a deterministic security layer and an agentic intelligence layer, and enforces a final decision — ALLOW, WARN, REQUIRE_APPROVAL, BLOCK, or REVOKE — before any action reaches a real resource.

```
AI Agent / Live LLM Agent
        ↓
FastAPI Gateway  POST /api/v1/execute    ← HTTP interface (deployable)
        ↓
Action Interceptor       normalize raw tool-call → Action
        ↓
Capability + Policy      deterministic checks (no LLM)
        ↓
Risk + Trajectory        scoring + session pattern analysis
        ↓
Counter-Agent / Judge    Groq LLM — only invoked for high-risk actions
        ↓
Decision Engine          deterministic final decision
        ↓
ALLOW / WARN / BLOCK / REVOKE
        ↓
Executor or Block
        ↓
Audit Event              append to audit.jsonl
```

---

## Team

| Engineer | Domain |
|---|---|
| **Durga** | Gateway, FastAPI, Deterministic Security Layer, Docker |
| **Yash** | Intelligence, Agentic Security, Live Agent, Dashboard UI |

---

## Project Structure

```
api/
  main.py             FastAPI gateway — HTTP interface to VEILPipeline

veil/
  config.py           Environment-driven settings (singleton)
  models/             Shared Pydantic schemas — Action, Decision, results
  gateway/            Interceptor, Normalizer, Executor
  security/           CapabilityManager, PolicyEngine, DataClassifier,
                      TrajectoryEngine, RiskEngine, InjectionDetector
  agents/             CounterAgent, JudgeAgent, DecisionEngine, RevocationEngine
  memory/             AuditEngine, ThreatMemory, FeedbackEngine

simulator/
  client/             DOOMSDAY CORP fake resources, tool stubs, agent profiles
    live_agent.py     Groq-powered live agent for Before/After demo
    demo.py           CLI Before/After demo script
  attacker/           Attack scenario generators

dashboard/
  app.py              Streamlit security dashboard (5 pages + Attack Lab)

tests/
  gateway/
  security/
  intelligence/
  memory/

Dockerfile            Single image for API + Dashboard
docker-compose.yml    Two-service stack (veil-api + veil-dashboard)
```

---

## Quick Start (Local)

### 1. Clone and create a virtual environment

```bash
git clone <repo>
cd veil
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
pip install -e .
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env — fill in GROQ_API_KEY
```

### 4. Create data directory

```bash
mkdir -p data
```

---

## Running the API

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

API docs available at: `http://localhost:8000/docs`

Health check: `curl http://localhost:8000/api/v1/health`

### API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Component health status |
| `POST` | `/api/v1/execute` | Run a single tool call through the pipeline |
| `POST` | `/api/v1/attacks/run` | Run a named scenario (e.g. `p0_attack`) |
| `GET` | `/api/v1/events` | Recent audit records (`?session_id=&limit=`) |
| `GET` | `/api/v1/agents` | All registered agent profiles |
| `GET` | `/api/v1/capabilities` | Full capability registry |

---

## Running the Dashboard

```bash
streamlit run dashboard/app.py
```

The dashboard connects to the API at `VEIL_API_URL` (default: `http://localhost:8000`).  
Start the API first, then the dashboard.

**Dashboard pages:**
- **Overview** — component health + aggregate stats
- **Live Activity** — auto-refresh table of recent audit events (3-second refresh)
- **Attack Timeline** — chronological event chain per session
- **Threat Investigation** — judge reasoning, injection signals, policy violations
- **Capabilities / Policy** — agent capability registry
- **⚔️ Attack Lab** — trigger live pipeline calls with Before/After toggle

---

## Running the Simulator (CLI)

```bash
# Run a named scenario through the full pipeline
python simulator/client/run.py --scenario p0_attack
python simulator/client/run.py --scenario support_legitimate
```

---

## Before/After Demo (Live LLM Agent)

Requires the API to be running and `GROQ_API_KEY` set.

```bash
# Compare: without VEIL vs. with VEIL, same malicious instruction
python simulator/client/demo.py --mode both

# Only the "before" path (direct tool call, no gateway)
python simulator/client/demo.py --mode before

# Only the "after" path (through VEIL gateway)
python simulator/client/demo.py --mode after

# Benign request (should be ALLOWED by VEIL)
python simulator/client/demo.py --mode benign
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Docker — Single Command Demo

```bash
# Copy and fill in your Groq API key
cp .env.example .env

# Start both services
docker compose up --build

# Dashboard: http://localhost:8501
# API docs:  http://localhost:8000/docs
# Health:    http://localhost:8000/api/v1/health
```

Both services share a `data/` volume so the dashboard reads the API's audit log in real time.

---

## Environment Variables

See [`.env.example`](.env.example) for the full list.

| Variable | Description | Default |
|---|---|---|
| `GROQ_API_KEY` | Groq API key (required for LLM agents) | — |
| `GROQ_MODEL_ID` | Groq model | `llama-3.3-70b-versatile` |
| `AUDIT_FILE_PATH` | Path to audit JSONL file | `data/audit.jsonl` |
| `THREAT_MEMORY_PATH` | Path to threat memory JSONL file | `data/threats.jsonl` |
| `VEIL_API_URL` | VEIL FastAPI base URL (used by dashboard + live agent) | `http://localhost:8000` |
| `GATEWAY_HOST` | API bind host | `0.0.0.0` |
| `GATEWAY_PORT` | API bind port | `8000` |
| `RISK_THRESHOLD_FOR_AGENTS` | Minimum risk level to invoke LLM agents | `HIGH` |

---

## P0 Demo Sequence (For Judges)

```
1. Open dashboard → Overview shows VEIL ACTIVE + all components green
2. Capabilities page → agent permission matrix
3. Attack Lab → run "Legitimate Request" → ALLOW → tool executed → audit event appears
4. Attack Lab → run "P0 Attack Chain" → step by step:
      Step 1: database.read    → BLOCK  (injection detected in purpose field)
      Step 2: file.read        → ALLOW  (cover action passes)
      Step 3: http.request     → REVOKE (PII exfiltration + external HTTP = capability revoked)
5. Attack Timeline → full session chain with judge reasoning highlighted
6. Before/After demo:
      python simulator/client/demo.py --mode both
      Without VEIL: tool executes (attacker succeeds)
      With VEIL:    BLOCK/REVOKE (attacker contained)
7. Component Health → all green
```

---

## Architecture Principle

The **deterministic layer** (capabilities, policy, classification) is the hard security boundary.  
It cannot be bypassed by an LLM. VEIL-Counter and VEIL-Judge are adversarial analysts — they raise  
decision quality for ambiguous cases. **The gateway enforces. The LLM advises.**
