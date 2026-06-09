#!/usr/bin/env python3
"""A trivial fake MCP server: reads JSON-RPC lines on stdin, echoes a result.

Only used to prove the proxy forwards/blocks correctly. It does NOT implement
the real MCP handshake — it just answers any tools/call it actually receives, so
we can observe which calls made it through the gate.
"""
import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("method") == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"].get("arguments", {})
        resp = {"jsonrpc": "2.0", "id": msg.get("id"),
                "result": {"upstream_received": name, "args_seen": args}}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
