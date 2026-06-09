"""mcp-gate: a runtime policy-enforcement proxy for the Model Context Protocol.

mcp-gate sits on the tool-call path between an MCP client (the agent host) and an
MCP server (the tools). Every `tools/call` request is intercepted, evaluated
against a declarative policy, and either forwarded, blocked, held for human
approval, or forwarded with arguments redacted. Every decision is written to a
hash-chained, tamper-evident audit log.

This is a FOUNDATION, not a finished enterprise product. It is designed to be
read, understood, run, and extended by you. Areas that need hardening before any
production use are marked with `# HARDENING:` comments throughout the source.
"""

from .decision import Decision, Effect
from .policy import Policy, PolicyError, load_policy
from .engine import PolicyEngine
from .audit import AuditLog
from .identity import (
    AgentIdentity, IdentityVerifier, HmacVerifier, Ed25519Verifier, Ed25519Signer,
)
from .threats import ThreatScanner, ScanResult, ThreatCategory
from .compliance import CONTROL_MAP, coverage_summary

__version__ = "0.3.0"

__all__ = [
    "Decision",
    "Effect",
    "Policy",
    "PolicyError",
    "load_policy",
    "PolicyEngine",
    "AuditLog",
    "AgentIdentity",
    "IdentityVerifier",
    "HmacVerifier",
    "Ed25519Verifier",
    "Ed25519Signer",
    "ThreatScanner",
    "ScanResult",
    "ThreatCategory",
    "CONTROL_MAP",
    "coverage_summary",
    "__version__",
]
