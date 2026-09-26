"""
simulator/client/tools.py

DOOMSDAY CORP tool stubs.

Each stub returns deterministic fake data. They never touch real systems.
The executor calls these when it dispatches an ALLOW decision.

Tool registry format: tool_name → callable(action) -> dict
"""

from __future__ import annotations

from typing import Any

from veil.models.action import Action
from simulator.client.resources import read_resource


def _database_read(action: Action) -> dict[str, Any]:
    rows = read_resource(action.resource)
    return {
        "tool": "database",
        "operation": "read",
        "resource": action.resource,
        "rows": rows,
        "row_count": len(rows),
    }


def _database_write(action: Action) -> dict[str, Any]:
    return {
        "tool": "database",
        "operation": "write",
        "resource": action.resource,
        "status": "ok",
        "rows_affected": 1,
    }


def _file_read(action: Action) -> dict[str, Any]:
    rows = read_resource(action.resource)
    return {
        "tool": "file",
        "operation": "read",
        "path": action.resource,
        "content": rows[0].get("content", "") if rows else "",
    }


def _file_write(action: Action) -> dict[str, Any]:
    return {
        "tool": "file",
        "operation": "write",
        "path": action.resource,
        "status": "ok",
        "bytes_written": 42,
    }


def _http_request(action: Action) -> dict[str, Any]:
    # Always return mock 200 — never makes a real HTTP call
    destination = action.destination or action.resource
    return {
        "tool": "http",
        "operation": "request",
        "url": destination,
        "status_code": 200,
        "response_body": '{"received": true}',
    }


def _email_read(action: Action) -> dict[str, Any]:
    return {
        "tool": "email",
        "operation": "read",
        "inbox": action.resource,
        "messages": [
            {"from": "sender@doomsday.corp", "subject": "Test", "body": "Hello."},
        ],
    }


def _email_send(action: Action) -> dict[str, Any]:
    return {
        "tool": "email",
        "operation": "send",
        "to": action.destination,
        "status": "queued",
    }


def _shell_execute(action: Action) -> dict[str, Any]:
    # This should never be called — shell is globally forbidden
    raise RuntimeError("shell.execute reached the tool stub — security boundary violated.")


# ---------------------------------------------------------------------------
# Tool registry — maps tool name → dict of operation → handler
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "database": {
        "read":  _database_read,
        "write": _database_write,
    },
    "file": {
        "read":  _file_read,
        "write": _file_write,
    },
    "http": {
        "request": _http_request,
    },
    "email": {
        "read": _email_read,
        "send": _email_send,
    },
    "shell": {
        "execute": _shell_execute,
    },
}


def dispatch(action: Action) -> dict[str, Any]:
    """
    Dispatch an Action to the appropriate tool stub.
    Called by the executor's tool_registry callable.
    """
    tool_ops = TOOL_REGISTRY.get(action.tool)
    if tool_ops is None:
        return {"error": f"Unknown tool: {action.tool}"}
    handler = tool_ops.get(action.operation)
    if handler is None:
        return {"error": f"Unknown operation '{action.operation}' for tool '{action.tool}'"}
    return handler(action)


def get_executor_registry() -> dict[str, Any]:
    """
    Returns a flat tool → callable dict suitable for ActionExecutor(tool_registry=...).
    The executor calls registry[tool](action); we wrap dispatch() per-tool.
    """
    return {
        tool: (lambda t: lambda action: dispatch(action))(tool)
        for tool in TOOL_REGISTRY
    }
