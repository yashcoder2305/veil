"""
api/main.py

VEIL FastAPI Gateway — HTTP interface to the VEILPipeline.

Exposes VEILPipeline.run() over HTTP so the dashboard, live agent, and demo
can submit requests without importing Python directly.

Run:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Pipeline singleton — created once at startup
# ---------------------------------------------------------------------------

_pipeline = None
_audit_engine = None
_capability_manager = None


def _get_pipeline():
    global _pipeline
    if _pipeline is None:
        from veil.pipeline import VEILPipeline
        _pipeline = VEILPipeline()
    return _pipeline


def _get_audit_engine():
    global _audit_engine
    if _audit_engine is None:
        from veil.memory.audit import AuditEngine
        _audit_engine = AuditEngine()
    return _audit_engine


def _get_capability_manager():
    global _capability_manager
    if _capability_manager is None:
        from veil.security.capabilities import CapabilityManager
        _capability_manager = CapabilityManager()
    return _capability_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm up the pipeline singleton at startup
    _get_pipeline()
    _get_audit_engine()
    _get_capability_manager()
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VEIL Gateway API",
    description="Verifiable Execution Isolation Layer — HTTP gateway",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ExecuteRequest(BaseModel):
    """Raw tool-call payload submitted by an agent."""
    agent_id: str
    session_id: str
    tool: str
    operation: str
    resource: str
    destination: str = ""
    purpose: str = ""
    provenance: str = ""
    data_classification: str = "UNKNOWN"
    metadata: dict[str, Any] = {}


class StepResult(BaseModel):
    step: int
    tool: str
    operation: str
    resource: str
    decision: str
    reason: str
    risk_level: str
    injection_detected: bool
    triggered_rules: list[str]
    confidence: float
    requires_human_review: bool
    revoked_capability: Optional[str]
    executed: bool
    execution_output: Optional[dict]


class ExecuteResponse(BaseModel):
    action_id: str
    session_id: str
    decision: str
    reason: str
    risk_level: str
    injection_detected: bool
    triggered_rules: list[str]
    confidence: float
    requires_human_review: bool
    revoked_capability: Optional[str]
    executed: bool
    execution_output: Optional[dict]


class AttackRunRequest(BaseModel):
    scenario: str
    session_id: Optional[str] = None


class AttackRunResponse(BaseModel):
    scenario: str
    session_id: str
    steps: list[StepResult]


class HealthResponse(BaseModel):
    status: str
    components: dict[str, dict]


class CapabilityGrantResponse(BaseModel):
    tool: str
    operations: list[str]
    resources: list[str]


class AgentProfileResponse(BaseModel):
    agent_id: str
    description: str
    grants: list[CapabilityGrantResponse]


class CapabilityResponse(BaseModel):
    agents: list[AgentProfileResponse]
    globally_forbidden: list[str]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _pipeline_result_to_step(pipeline_result, step: int) -> StepResult:
    from veil.gateway.executor import ExecutionResult
    er = pipeline_result.execution_result
    return StepResult(
        step=step,
        tool=pipeline_result.action.tool,
        operation=pipeline_result.action.operation,
        resource=pipeline_result.action.resource,
        decision=pipeline_result.decision_result.decision.value,
        reason=pipeline_result.decision_result.reason,
        risk_level=pipeline_result.risk_result.level.value if pipeline_result.risk_result else "UNKNOWN",
        injection_detected=pipeline_result.injection_result.detected if pipeline_result.injection_result else False,
        triggered_rules=list(pipeline_result.decision_result.triggered_rules),
        confidence=pipeline_result.decision_result.confidence,
        requires_human_review=pipeline_result.decision_result.requires_human_review,
        revoked_capability=pipeline_result.decision_result.revoked_capability,
        executed=er.executed,
        execution_output=er.tool_output if er.executed else None,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/health
# ---------------------------------------------------------------------------

@app.get("/api/v1/health", response_model=HealthResponse, tags=["meta"])
def health() -> HealthResponse:
    """
    Ping each VEIL component and return per-component green/red status.
    """
    from veil.config import settings

    components: dict[str, dict] = {}

    # Pipeline instantiation
    try:
        p = _get_pipeline()
        components["pipeline"] = {"status": "ok", "detail": "VEILPipeline ready"}
    except Exception as exc:
        components["pipeline"] = {"status": "error", "detail": str(exc)}

    # Capability registry
    try:
        mgr = _get_capability_manager()
        profiles = mgr.all_profiles()
        components["capabilities"] = {
            "status": "ok",
            "detail": f"{len(profiles)} agent profiles loaded",
        }
    except Exception as exc:
        components["capabilities"] = {"status": "error", "detail": str(exc)}

    # Audit file writable
    try:
        audit_path: Path = settings.audit_file_path
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        # Test write access
        test_path = audit_path.parent / ".write_test"
        test_path.write_text("ok")
        test_path.unlink()
        components["audit"] = {
            "status": "ok",
            "detail": f"Audit file path: {audit_path}",
        }
    except Exception as exc:
        components["audit"] = {"status": "error", "detail": str(exc)}

    # Groq API key present
    try:
        key = settings.groq_api_key
        components["groq"] = {"status": "ok", "detail": "API key present"}
    except EnvironmentError:
        components["groq"] = {"status": "warning", "detail": "GROQ_API_KEY not set — LLM agents disabled"}
    except Exception as exc:
        components["groq"] = {"status": "error", "detail": str(exc)}

    overall = "ok" if all(c["status"] == "ok" for c in components.values()) else "degraded"
    return HealthResponse(status=overall, components=components)


# ---------------------------------------------------------------------------
# POST /api/v1/execute
# ---------------------------------------------------------------------------

@app.post("/api/v1/execute", response_model=ExecuteResponse, tags=["pipeline"])
def execute(request: ExecuteRequest) -> ExecuteResponse:
    """
    Accept a raw tool-call, run the full VEIL pipeline, return structured result.
    """
    pipeline = _get_pipeline()

    raw_payload = request.model_dump()
    try:
        result = pipeline.run(raw_payload)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {exc}")

    er = result.execution_result
    return ExecuteResponse(
        action_id=result.action.action_id,
        session_id=result.action.session_id,
        decision=result.decision_result.decision.value,
        reason=result.decision_result.reason,
        risk_level=result.risk_result.level.value if result.risk_result else "UNKNOWN",
        injection_detected=result.injection_result.detected if result.injection_result else False,
        triggered_rules=list(result.decision_result.triggered_rules),
        confidence=result.decision_result.confidence,
        requires_human_review=result.decision_result.requires_human_review,
        revoked_capability=result.decision_result.revoked_capability,
        executed=er.executed,
        execution_output=er.tool_output if er.executed else None,
    )


# ---------------------------------------------------------------------------
# POST /api/v1/attacks/run
# ---------------------------------------------------------------------------

@app.post("/api/v1/attacks/run", response_model=AttackRunResponse, tags=["attacks"])
def attacks_run(request: AttackRunRequest) -> AttackRunResponse:
    """
    Run a named simulator scenario through the live pipeline.
    A fresh session_id is generated per request to avoid trajectory bleed.
    """
    from simulator.client.scenarios import SCENARIOS

    scenario_fn = SCENARIOS.get(request.scenario)
    if scenario_fn is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario '{request.scenario}'. Available: {list(SCENARIOS.keys())}",
        )

    # Fresh session per request — prevents trajectory accumulation across demo runs
    session_id = request.session_id or f"sess-{request.scenario}-{uuid.uuid4().hex[:8]}"

    actions = scenario_fn(session_id=session_id)

    # Each scenario run needs its own pipeline so trajectory/revocation state is fresh
    from veil.pipeline import VEILPipeline
    scenario_pipeline = VEILPipeline()

    steps: list[StepResult] = []
    for i, action in enumerate(actions, start=1):
        raw_payload = action.model_dump()
        # Override timestamps to avoid frozen model issues
        raw_payload["timestamp"] = action.timestamp.isoformat()
        try:
            pr = scenario_pipeline.run(raw_payload)
            steps.append(_pipeline_result_to_step(pr, i))
        except Exception as exc:
            # Don't let one bad step kill the whole run
            steps.append(StepResult(
                step=i,
                tool=action.tool,
                operation=action.operation,
                resource=action.resource,
                decision="ERROR",
                reason=str(exc),
                risk_level="UNKNOWN",
                injection_detected=False,
                triggered_rules=[],
                confidence=0.0,
                requires_human_review=False,
                revoked_capability=None,
                executed=False,
                execution_output=None,
            ))

    return AttackRunResponse(
        scenario=request.scenario,
        session_id=session_id,
        steps=steps,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/events
# ---------------------------------------------------------------------------

@app.get("/api/v1/events", tags=["audit"])
def events(
    session_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    """
    Return recent audit records, optionally filtered by session_id.
    """
    audit = _get_audit_engine()
    records = audit.query(session_id=session_id)
    # Return last N records (most recent first)
    return [r.model_dump() for r in records[-limit:][::-1]]


# ---------------------------------------------------------------------------
# GET /api/v1/agents
# ---------------------------------------------------------------------------

@app.get("/api/v1/agents", response_model=list[AgentProfileResponse], tags=["registry"])
def agents() -> list[AgentProfileResponse]:
    """Return all registered agent profiles and their capability grants."""
    mgr = _get_capability_manager()
    result = []
    for profile in mgr.all_profiles():
        result.append(AgentProfileResponse(
            agent_id=profile.agent_id,
            description=profile.description,
            grants=[
                CapabilityGrantResponse(
                    tool=g.tool,
                    operations=sorted(g.operations),
                    resources=sorted(g.resources),
                )
                for g in profile.grants
            ],
        ))
    return result


# ---------------------------------------------------------------------------
# GET /api/v1/capabilities
# ---------------------------------------------------------------------------

@app.get("/api/v1/capabilities", response_model=CapabilityResponse, tags=["registry"])
def capabilities() -> CapabilityResponse:
    """Return full capability registry with globally forbidden list."""
    mgr = _get_capability_manager()
    profiles = []
    for profile in mgr.all_profiles():
        profiles.append(AgentProfileResponse(
            agent_id=profile.agent_id,
            description=profile.description,
            grants=[
                CapabilityGrantResponse(
                    tool=g.tool,
                    operations=sorted(g.operations),
                    resources=sorted(g.resources),
                )
                for g in profile.grants
            ],
        ))
    return CapabilityResponse(
        agents=profiles,
        globally_forbidden=["shell.execute", "shell.spawn"],
    )


# ===========================================================================
# VULNERABLE SERVER  (no auth, no policy, no VEIL — raw access)
#
# These endpoints simulate what a company server looks like WITHOUT VEIL.
# Any request is fulfilled immediately. Used for the Before/After demo.
#
# Routes:
#   GET  /vulnerable/db/{resource}   — dump any table, no checks
#   POST /vulnerable/execute         — run any tool call directly
#   POST /vulnerable/attack          — run a full attack scenario, all steps execute
# ===========================================================================

@app.get("/vulnerable/db/{resource}", tags=["⚠️ Vulnerable Server"])
def vulnerable_db(resource: str) -> dict:
    """
    NO SECURITY — returns full database table for any resource, to any caller.
    Simulates a company AI server with no access control layer.
    """
    from simulator.client.resources import read_resource, RESOURCES

    rows = read_resource(resource)
    meta = RESOURCES.get(resource)

    return {
        "veil_active": False,
        "warning": "NO SECURITY CONTROLS — VEIL is not protecting this endpoint",
        "resource": resource,
        "classification": meta.classification.value if meta else "UNKNOWN",
        "description": meta.description if meta else "",
        "row_count": len(rows),
        "data": rows,
    }


@app.post("/vulnerable/execute", tags=["⚠️ Vulnerable Server"])
def vulnerable_execute(request: ExecuteRequest) -> dict:
    """
    NO SECURITY — dispatches any tool call directly to the tool, bypassing VEIL.
    The agent's identity, purpose, and provenance are never checked.
    """
    from simulator.client.tools import dispatch
    from veil.models.action import Action

    action = Action(
        agent_id=request.agent_id,
        session_id=request.session_id,
        tool=request.tool,
        operation=request.operation,
        resource=request.resource,
        destination=request.destination,
        purpose=request.purpose,
        provenance=request.provenance,
        metadata=request.metadata,
    )

    try:
        output = dispatch(action)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "veil_active": False,
        "warning": "NO SECURITY CONTROLS — action was executed without any enforcement",
        "agent_id": request.agent_id,
        "tool": request.tool,
        "operation": request.operation,
        "resource": request.resource,
        "destination": request.destination or None,
        "executed": True,
        "output": output,
    }


@app.post("/vulnerable/attack", tags=["⚠️ Vulnerable Server"])
def vulnerable_attack(request: AttackRunRequest) -> dict:
    """
    NO SECURITY — runs a full named attack scenario against tool stubs.
    Every step executes regardless of payload content, injection signals, or
    data classification. No audit trail is written.
    """
    from simulator.client.scenarios import SCENARIOS
    from simulator.client.tools import dispatch

    scenario_fn = SCENARIOS.get(request.scenario)
    if scenario_fn is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario '{request.scenario}'. Available: {list(SCENARIOS.keys())}",
        )

    session_id = request.session_id or f"vuln-{request.scenario}-{uuid.uuid4().hex[:6]}"
    actions = scenario_fn(session_id=session_id)

    steps = []
    for i, action in enumerate(actions, start=1):
        try:
            output = dispatch(action)
            steps.append({
                "step": i,
                "tool": action.tool,
                "operation": action.operation,
                "resource": action.resource,
                "destination": action.destination or None,
                "purpose": action.purpose,
                "executed": True,
                "output": output,
            })
        except Exception as exc:
            steps.append({
                "step": i,
                "tool": action.tool,
                "operation": action.operation,
                "resource": action.resource,
                "executed": False,
                "error": str(exc),
            })

    return {
        "veil_active": False,
        "warning": "NO SECURITY CONTROLS — all steps executed without enforcement",
        "scenario": request.scenario,
        "session_id": session_id,
        "total_steps": len(steps),
        "steps_executed": sum(1 for s in steps if s.get("executed")),
        "steps": steps,
    }
