"""Gate: the Policy Enforcement Point.

This is the transport-agnostic brain of the proxy. Give it a parsed JSON-RPC
message and the calling identity; it tells you what to send onward and what (if
anything) to send back to the agent. It stays free of any I/O so it can be unit
tested against thousands of cases — which is exactly how you drive the
false-positive rate down: not by claiming perfection, but by building a corpus
of (call, expected-decision) cases and running them on every change.

The handle_request() method returns a GateOutcome describing one of:
  - forward this (possibly redacted) message to the upstream server
  - short-circuit: return this JSON-RPC error to the agent, forward nothing
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from .audit import AuditLog
from .decision import Decision, Effect
from .engine import PolicyEngine
from .enforce import (
    FailMode,
    build_denial_response,
    jsonrpc_error,
    redact_arguments,
    INTERNAL_ERROR_CODE,
)
from .identity import AgentIdentity

log = logging.getLogger("mcpgate")

# The MCP method we govern. Other methods (initialize, tools/list, ping, ...)
# pass through untouched — we only gate ACTIONS, not discovery/handshake.
GOVERNED_METHOD = "tools/call"


@dataclass
class GateOutcome:
    forward_message: dict[str, Any] | None     # send upstream, or None
    response_to_agent: dict[str, Any] | None   # send back now, or None
    decision: Decision | None                  # None for ungoverned messages


# An approval hook lets you plug in human-in-the-loop. It receives the call
# context and must return True (approved) or False (rejected). The default
# rejects, because REQUIRE_APPROVAL with no approver wired up should fail safe.
ApprovalHook = Callable[[str, dict[str, Any], AgentIdentity, Decision], bool]


def _default_approval_hook(tool, args, identity, decision) -> bool:
    log.warning("REQUIRE_APPROVAL for tool=%s but no approval hook configured; "
                "rejecting (fail-safe).", tool)
    return False


class Gate:
    def __init__(self, engine: PolicyEngine, audit: AuditLog, *,
                 fail_mode: FailMode = FailMode.CLOSED,
                 approval_hook: ApprovalHook | None = None) -> None:
        self.engine = engine
        self.audit = audit
        self.fail_mode = fail_mode
        self.approval_hook = approval_hook or _default_approval_hook

    def handle_request(self, message: dict[str, Any],
                       identity: AgentIdentity, session_id: str) -> GateOutcome:
        method = message.get("method")
        if method != GOVERNED_METHOD:
            # Not a tool call — pass through. Handshake and discovery are not
            # actions and are not gated.
            return GateOutcome(forward_message=message, response_to_agent=None,
                               decision=None)

        request_id = message.get("id")
        params = message.get("params") or {}
        tool = params.get("name", "")
        arguments = params.get("arguments") or {}

        try:
            decision = self.engine.evaluate(tool, arguments, identity, session_id)
        except Exception:  # engine bug, malformed condition, etc.
            log.exception("policy engine raised; applying fail_mode=%s",
                          self.fail_mode.value)
            return self._handle_engine_failure(message, request_id, tool,
                                               arguments, identity, session_id)

        # Audit EVERY decision, including allows. This is the evidence trail.
        self.audit.record(
            session_id=session_id, identity=identity, tool=tool,
            args=arguments, decision=decision,
            policy_name=self.engine.policy.name,
            policy_version=self.engine.policy.version,
        )

        if decision.effect is Effect.ALLOW:
            self.engine.commit_budget(tool, arguments, decision, session_id)
            return GateOutcome(forward_message=message,
                               response_to_agent=None, decision=decision)

        if decision.effect is Effect.REDACT:
            new_msg = dict(message)
            new_params = dict(params)
            new_params["arguments"] = redact_arguments(arguments,
                                                       decision.redact_fields)
            new_msg["params"] = new_params
            self.engine.commit_budget(tool, arguments, decision, session_id)
            return GateOutcome(forward_message=new_msg,
                               response_to_agent=None, decision=decision)

        if decision.effect is Effect.REQUIRE_APPROVAL:
            approved = self.approval_hook(tool, arguments, identity, decision)
            if approved:
                self.engine.commit_budget(tool, arguments, decision, session_id)
                return GateOutcome(forward_message=message,
                                   response_to_agent=None, decision=decision)
            return GateOutcome(
                forward_message=None,
                response_to_agent=build_denial_response(request_id, decision),
                decision=decision,
            )

        # DENY
        return GateOutcome(
            forward_message=None,
            response_to_agent=build_denial_response(request_id, decision),
            decision=decision,
        )

    def _handle_engine_failure(self, message, request_id, tool, arguments,
                               identity, session_id) -> GateOutcome:
        if self.fail_mode is FailMode.OPEN:
            # Availability-first: forward despite the error. Still audited so the
            # gap is visible after the fact.
            self._safe_audit_failure(session_id, identity, tool, arguments,
                                     forwarded=True)
            return GateOutcome(forward_message=message,
                               response_to_agent=None, decision=None)
        # fail-closed
        self._safe_audit_failure(session_id, identity, tool, arguments,
                                 forwarded=False)
        return GateOutcome(
            forward_message=None,
            response_to_agent=jsonrpc_error(
                request_id, INTERNAL_ERROR_CODE,
                "mcp-gate: policy evaluation failed; blocked (fail-closed)"),
            decision=None,
        )

    def _safe_audit_failure(self, session_id, identity, tool, arguments,
                            forwarded: bool) -> None:
        try:
            from .decision import Decision as _D, Effect as _E
            self.audit.record(
                session_id=session_id, identity=identity, tool=tool,
                args=arguments,
                decision=_D(effect=(_E.ALLOW if forwarded else _E.DENY),
                            rule_id="__engine_failure__",
                            reason=f"engine failure; fail_mode={self.fail_mode.value}"),
                policy_name=self.engine.policy.name,
                policy_version=self.engine.policy.version,
            )
        except Exception:
            log.exception("failed to audit engine-failure event")
