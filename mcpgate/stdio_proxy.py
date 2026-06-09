"""Stdio proxy: gate an MCP server that speaks over stdin/stdout.

Architecture (stdio transport):

    MCP client (agent host)
        | stdin/stdout  (talks to mcp-gate as if it were the server)
        v
    mcp-gate stdio proxy   <-- this module
        | stdin/stdout  (spawns the REAL server as a subprocess)
        v
    upstream MCP server

Per the MCP spec, stdio transport has no client<->server auth and the server is
launched as a subprocess configured by environment variables — which is exactly
why a proxy slots in cleanly here: we become the subprocess the client launches,
and we launch the real server ourselves.

MCP messages are newline-delimited JSON-RPC 2.0 objects. We read a line from the
client, parse it, run it through the Gate, and either forward it to the upstream
subprocess or answer the client directly with a denial. Responses from upstream
are streamed back unchanged.

# HARDENING:
#  - This reference proxy reads identity from the MCPGATE_AGENT_TOKEN env var,
#    set when the client launches the proxy. For stdio that is the natural
#    channel (the spec uses env for stdio config). Validate token freshness.
#  - A truly robust proxy must handle: partial lines, huge messages (cap line
#    size), upstream crash/restart, and backpressure. The threading model below
#    is intentionally simple and readable; review it for your load profile.
#  - Notifications (no `id`) and batches need care; tools/call always has an id.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
from typing import Any

from .gate import Gate
from .identity import (
    AgentIdentity, IdentityError, IdentityVerifier, HmacVerifier,
)

log = logging.getLogger("mcpgate.stdio")


class StdioProxy:
    def __init__(self, gate: Gate, upstream_cmd: list[str], *,
                 identity_secret: bytes | None = None,
                 verifier: IdentityVerifier | None = None,
                 session_id: str = "stdio-session",
                 max_age_seconds: float | None = 3600.0) -> None:
        self.gate = gate
        self.upstream_cmd = upstream_cmd
        # A verifier (HMAC, Ed25519, or custom) takes precedence; otherwise fall
        # back to building an HMAC verifier from a raw secret for convenience.
        if verifier is None and identity_secret is not None:
            verifier = HmacVerifier(identity_secret)
        self.verifier = verifier
        self.session_id = session_id
        self.max_age_seconds = max_age_seconds
        self._proc: subprocess.Popen[bytes] | None = None

    def _resolve_identity(self) -> AgentIdentity:
        token = os.environ.get("MCPGATE_AGENT_TOKEN")
        if not token or self.verifier is None:
            # No verifiable identity provided: treat as anonymous. Whether that
            # is allowed is up to the policy (it can deny agent_id 'anonymous').
            return AgentIdentity.anonymous()
        try:
            return self.verifier.verify(token, self.max_age_seconds)
        except IdentityError as exc:
            log.warning("identity verification failed: %s; using anonymous", exc)
            return AgentIdentity.anonymous()

    def run(self) -> int:
        identity = self._resolve_identity()
        self._proc = subprocess.Popen(
            self.upstream_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,  # surface upstream errors to the operator
        )
        assert self._proc.stdin and self._proc.stdout

        # Pump upstream -> client on a background thread.
        pump = threading.Thread(target=self._pump_upstream_to_client, daemon=True)
        pump.start()

        client_in = sys.stdin.buffer
        upstream_out = self._proc.stdin
        try:
            for raw in client_in:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                self._handle_client_line(line, identity, upstream_out)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                upstream_out.close()
            except Exception:
                pass
            self._proc.wait(timeout=5)
        return self._proc.returncode or 0

    def _handle_client_line(self, line: str, identity: AgentIdentity,
                            upstream_out: Any) -> None:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            log.error("dropping non-JSON line from client")
            return

        outcome = self.gate.handle_request(message, identity, self.session_id)

        if outcome.response_to_agent is not None:
            # Denied/approval-rejected/fail-closed: answer the client directly.
            self._write_client(outcome.response_to_agent)

        if outcome.forward_message is not None:
            data = (json.dumps(outcome.forward_message,
                               separators=(",", ":")) + "\n").encode()
            upstream_out.write(data)
            upstream_out.flush()

    def _pump_upstream_to_client(self) -> None:
        assert self._proc and self._proc.stdout
        for raw in self._proc.stdout:
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()

    def _write_client(self, obj: dict[str, Any]) -> None:
        sys.stdout.buffer.write((json.dumps(obj, separators=(",", ":")) + "\n").encode())
        sys.stdout.buffer.flush()
