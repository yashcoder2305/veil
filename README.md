# VEIL — Verifiable Execution Isolation Layer

> "The LLM can be compromised. The prompt can be malicious. VEIL still controls the door."

Runtime security boundary for AI agents — IBM Bob 2.0 Hackathon | **Team Doomsday**

---

## What VEIL Does

VEIL intercepts every tool call an AI agent attempts to make, evaluates it through a deterministic security layer and an agentic intelligence layer, and enforces a final decision — ALLOW, WARN, REQUIRE_APPROVAL, BLOCK, or REVOKE — before any action reaches a real resource.

```
AI Agent
    ↓
Action Interceptor       normalize raw tool-call → Action
    ↓
Capability + Policy      deterministic checks (no LLM)
    ↓
Risk + Trajectory        scoring + session pattern analysis
    ↓
Counter-Agent / Judge    watsonx.ai — only invoked for high-risk actions
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
| **Durga** | Gateway & Deterministic Security Layer |
| **Yash** | Intelligence & Agentic Security Layer |

---

## Project Structure

```
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
  attacker/           Attack scenario generators

dashboard/
  app.py              Streamlit security dashboard

tests/
  gateway/
  security/
  intelligence/
  memory/
```

---

## Setup

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
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env — fill in WATSONX_API_KEY and WATSONX_PROJECT_ID
```

### 4. Create data directory

```bash
mkdir data
```

---

## Running the Simulator

```bash
# Run a named scenario through the full VEIL pipeline
python simulator/client/run.py --scenario p0_attack

# Run the legitimate support agent scenario
python simulator/client/run.py --scenario support_legitimate
```

---

## Running the Dashboard

```bash
streamlit run dashboard/app.py
```

The dashboard reads from `data/audit.jsonl`. Run a simulator scenario first to populate it.

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Environment Variables

See [`.env.example`](.env.example) for the full list. Required variables:

| Variable | Description |
|---|---|
| `WATSONX_API_KEY` | IBM Cloud API key |
| `WATSONX_PROJECT_ID` | watsonx.ai project ID |
| `WATSONX_MODEL_ID` | Model ID (default: `ibm/granite-13b-instruct-v2`) |
| `AUDIT_FILE_PATH` | Path to audit JSONL file (default: `data/audit.jsonl`) |
| `THREAT_MEMORY_PATH` | Path to threat memory JSONL file (default: `data/threats.jsonl`) |

---

## P0 Demo Scenario

**Prompt injection → PII read → transform → external HTTP transfer → VEIL blocks + revokes network capability + full audit trail in dashboard.**

1. Start dashboard: `streamlit run dashboard/app.py`
2. Run attack: `python simulator/client/run.py --scenario p0_attack`
3. Watch the dashboard show the blocked multi-step chain with REVOKE decision.
