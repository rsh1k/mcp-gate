"""Audit log: tamper-evident, append-only, and compliance-shaped.

Every decision — allow, deny, approval, redact — is written here. Two design
choices make this more than a log file:

1. Hash chaining. Each record includes the SHA-256 of the previous record. Any
   edit or deletion of a past record breaks the chain and is detectable by
   verify(). This gives you tamper-EVIDENCE (not tamper-proofing; for that you
   anchor the chain head externally — see HARDENING note).

2. Compliance-shaped fields. Each record captures who (agent identity), what
   (tool + arguments hash), when, under which policy version, what decision, and
   why. That maps directly onto the audit-trail and decision-explainability
   obligations enterprises are scrambling to meet before the EU AI Act's
   high-risk provisions take effect (August 2026). The same enforcement stream
   becomes your evidence generator.

# HARDENING:
#  - Argument VALUES are hashed, not stored, by default, to avoid persisting PII
#    in the audit log. If you need full payloads for forensics, store them in a
#    separate, access-controlled, encrypted sink — never the same file.
#  - For true tamper-proofing, periodically publish the latest chain head hash
#    to an external write-once medium (e.g. a transparency log, object storage
#    with object-lock, or a notary service). The chain proves internal
#    consistency; the external anchor proves nothing was truncated.
#  - This file-based sink is single-writer. For concurrency, serialize writes
#    through one process or use an append-only DB.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .decision import Decision
from .identity import AgentIdentity

GENESIS = "0" * 64


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_args(args: dict[str, Any]) -> str:
    """Stable hash of arguments without storing their (possibly sensitive) values."""
    canonical = json.dumps(args or {}, separators=(",", ":"), sort_keys=True,
                           default=str).encode()
    return _sha256_hex(canonical)


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    timestamp: float
    session_id: str
    agent_id: str
    agent_roles: list[str]
    tool: str
    args_hash: str
    decision: dict[str, Any]
    policy_name: str
    policy_version: str
    prev_hash: str

    def body(self) -> dict[str, Any]:
        # Everything EXCEPT this record's own hash. The hash is computed over
        # this body, so it can't include itself.
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "agent_roles": self.agent_roles,
            "tool": self.tool,
            "args_hash": self.args_hash,
            "decision": self.decision,
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        canonical = json.dumps(self.body(), separators=(",", ":"),
                               sort_keys=True).encode()
        return _sha256_hex(canonical)


class AuditLog:
    """Append-only JSONL audit log with a SHA-256 hash chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._seq, self._last_hash = self._recover_state()

    def _recover_state(self) -> tuple[int, str]:
        """On startup, read the tail to continue the chain across restarts."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        last_line = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last_line = line
        if last_line is None:
            return 0, GENESIS
        rec = json.loads(last_line)
        return int(rec["seq"]) + 1, str(rec["hash"])

    def record(self, *, session_id: str, identity: AgentIdentity, tool: str,
               args: dict[str, Any], decision: Decision,
               policy_name: str, policy_version: str) -> AuditRecord:
        with self._lock:
            rec = AuditRecord(
                seq=self._seq,
                timestamp=time.time(),
                session_id=session_id,
                agent_id=identity.agent_id,
                agent_roles=sorted(identity.roles),
                tool=tool,
                args_hash=_hash_args(args),
                decision=decision.to_audit_dict(),
                policy_name=policy_name,
                policy_version=policy_version,
                prev_hash=self._last_hash,
            )
            rec_hash = rec.compute_hash()
            line = json.dumps({**rec.body(), "hash": rec_hash},
                              separators=(",", ":"), sort_keys=True)
            # Append + fsync so a crash can't lose an acknowledged decision.
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._seq += 1
            self._last_hash = rec_hash
            return rec

    def verify(self) -> tuple[bool, str]:
        """Re-walk the whole chain. Returns (ok, message).

        Detects: edited records, reordering, deletions, and a broken prev_hash
        link. This is what you run to PROVE the log wasn't tampered with.
        """
        if not self.path.exists():
            return True, "empty log"
        prev = GENESIS
        expected_seq = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                stored_hash = rec.pop("hash")
                if int(rec["seq"]) != expected_seq:
                    return False, f"seq gap at line {lineno}: {rec['seq']} != {expected_seq}"
                if rec["prev_hash"] != prev:
                    return False, f"chain break at line {lineno} (seq {rec['seq']})"
                recomputed = _sha256_hex(
                    json.dumps(rec, separators=(",", ":"), sort_keys=True).encode()
                )
                if recomputed != stored_hash:
                    return False, f"hash mismatch at line {lineno} (seq {rec['seq']})"
                prev = stored_hash
                expected_seq += 1
        return True, f"chain valid: {expected_seq} records"

    def __iter__(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
