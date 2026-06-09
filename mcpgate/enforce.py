"""Enforcement: turning a Decision into a concrete action on the wire.

The engine decides; this module enacts. It knows about JSON-RPC shapes (because
MCP is JSON-RPC 2.0) and about the two failure postures every security tool must
let the operator choose between:

  fail-closed  if the proxy itself errors (bad policy load, engine exception),
               BLOCK the call. Safe default for high-assurance environments.
  fail-open    if the proxy errors, FORWARD the call. For availability-first
               environments that would rather risk an unchecked call than break
               the agent. This must be a conscious operator choice — never a
               silent default.

MCP error codes follow JSON-RPC. We use -32001 (a server-defined error) for
policy denials so the agent receives a clean, explainable rejection rather than
a transport hang.
"""

from __future__ import annotations

import copy
import enum
from typing import Any

from .decision import Decision, Effect

POLICY_DENIED_CODE = -32001
APPROVAL_REQUIRED_CODE = -32002
INTERNAL_ERROR_CODE = -32603  # standard JSON-RPC internal error

REDACTED = "***REDACTED***"


class FailMode(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"


def redact_arguments(arguments: dict[str, Any],
                     fields: tuple[str, ...]) -> dict[str, Any]:
    """Return a copy of arguments with the given dotted paths masked.

    Missing paths are skipped silently — redacting something that isn't there is
    a no-op, never an error.
    """
    result = copy.deepcopy(arguments or {})
    for path in fields:
        parts = path.split(".")
        cur: Any = result
        ok = True
        for p in parts[:-1]:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                ok = False
                break
        if ok and isinstance(cur, dict) and parts[-1] in cur:
            cur[parts[-1]] = REDACTED
    return result


def jsonrpc_error(request_id: Any, code: int, message: str,
                  data: dict[str, Any] | None = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


def build_denial_response(request_id: Any, decision: Decision) -> dict[str, Any]:
    code = (APPROVAL_REQUIRED_CODE if decision.effect is Effect.REQUIRE_APPROVAL
            else POLICY_DENIED_CODE)
    return jsonrpc_error(
        request_id,
        code,
        f"mcp-gate: {decision.effect.value} by rule '{decision.rule_id}'",
        data={"reason": decision.reason, "rule_id": decision.rule_id},
    )
