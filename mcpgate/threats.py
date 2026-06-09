"""Threat scanner: heuristic detection of injection & dangerous arguments.

The NIST NCCoE concept paper on AI agent identity & authorization (Feb 2026)
explicitly calls out "controls to prevent and mitigate prompt injection
techniques" as in-scope. The OWASP Top 10 for Agentic Applications names Tool
Misuse (ASI02) and Agent Goal Hijack (ASI01) among the top risks. This module
gives mcp-gate a content-inspection layer that policies can invoke to flag tool
calls whose ARGUMENTS carry signs of injected instructions, command injection,
secret exfiltration, or path traversal.

Design stance — read carefully:
  This is a HEURISTIC signal, not a classifier with a calibrated false-positive
  rate. It is deliberately conservative and EXPLAINABLE: every hit names the
  pattern and category that fired, so an analyst can see exactly why. Heuristics
  produce false positives by nature; the intended use is to feed a
  REQUIRE_APPROVAL effect (hold for a human) rather than a hard DENY, so a false
  hit costs a review click, not a broken workflow. That is the honest way to use
  pattern matching in a security control.

# HARDENING: pattern matching catches known shapes, not novel/obfuscated
# attacks. For stronger coverage, layer a dedicated injection classifier (an LLM
# guard or a trained model) behind the same ThreatScanner interface. Keep this
# heuristic layer as a cheap, deterministic first pass that never needs a network
# call and can't itself be prompt-injected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"      # OWASP ASI01 / ASI02
    COMMAND_INJECTION = "command_injection"    # OWASP ASI05 (code execution)
    SECRET_EXFIL = "secret_exfiltration"       # OWASP ASI02 tool misuse
    PATH_TRAVERSAL = "path_traversal"          # OWASP ASI02
    SUSPICIOUS_URL = "suspicious_url"          # data egress to attacker host


# Each pattern is (compiled_regex, category, human_label, weight).
# Weights let policy set a threshold instead of firing on any single weak signal,
# which is the main lever for trading off sensitivity vs false positives.
_PATTERNS: list[tuple[re.Pattern[str], ThreatCategory, str, int]] = [
    # --- prompt injection / goal hijack -----------------------------------
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
     ThreatCategory.PROMPT_INJECTION, "ignore-previous-instructions", 4),
    (re.compile(r"disregard\s+(the\s+)?(system|above|prior)", re.I),
     ThreatCategory.PROMPT_INJECTION, "disregard-system", 3),
    (re.compile(r"\byou\s+are\s+now\b|\bnew\s+role\b|\bact\s+as\b", re.I),
     ThreatCategory.PROMPT_INJECTION, "role-reassignment", 2),
    (re.compile(r"reveal|exfiltrate|leak|send.*(api[_\s-]?key|password|secret|token)", re.I),
     ThreatCategory.PROMPT_INJECTION, "instruction-to-exfiltrate", 3),
    (re.compile(r"</?(system|assistant|tool)[>\]]", re.I),
     ThreatCategory.PROMPT_INJECTION, "fake-role-delimiter", 3),

    # --- command / code injection -----------------------------------------
    (re.compile(r";\s*(rm|del|format|shutdown|reboot)\b", re.I),
     ThreatCategory.COMMAND_INJECTION, "chained-destructive-command", 4),
    (re.compile(r"\$\(|\bsubprocess\b|\bos\.system\b|\beval\(|\bexec\(", re.I),
     ThreatCategory.COMMAND_INJECTION, "code-exec-primitive", 3),
    (re.compile(r"\|\s*(sh|bash|powershell|cmd)\b", re.I),
     ThreatCategory.COMMAND_INJECTION, "pipe-to-shell", 4),

    # --- secret exfiltration ----------------------------------------------
    (re.compile(r"AKIA[0-9A-Z]{16}"),
     ThreatCategory.SECRET_EXFIL, "aws-access-key-id", 4),
    (re.compile(r"-----BEGIN\s+(RSA|OPENSSH|EC|DSA|PGP)\s+PRIVATE\s+KEY-----"),
     ThreatCategory.SECRET_EXFIL, "private-key-block", 5),
    (re.compile(r"\b(sk|rk)-[A-Za-z0-9]{20,}\b"),
     ThreatCategory.SECRET_EXFIL, "api-secret-token", 3),

    # --- path traversal ----------------------------------------------------
    (re.compile(r"\.\./|\.\.\\"),
     ThreatCategory.PATH_TRAVERSAL, "dot-dot-slash", 3),
    (re.compile(r"/etc/(passwd|shadow|sudoers)\b"),
     ThreatCategory.PATH_TRAVERSAL, "sensitive-system-file", 4),

    # --- suspicious egress URLs -------------------------------------------
    (re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}"),  # raw IP URLs
     ThreatCategory.SUSPICIOUS_URL, "raw-ip-url", 2),
    (re.compile(r"https?://[^\s\"']*\.(?:tk|top|xyz|click|zip|mov)\b", re.I),
     ThreatCategory.SUSPICIOUS_URL, "high-risk-tld", 2),
]


@dataclass(frozen=True)
class ThreatHit:
    category: ThreatCategory
    label: str
    weight: int
    field_path: str
    excerpt: str


@dataclass(frozen=True)
class ScanResult:
    hits: tuple[ThreatHit, ...] = ()
    score: int = 0
    categories: frozenset[ThreatCategory] = field(default_factory=frozenset)

    @property
    def clean(self) -> bool:
        return not self.hits

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "categories": sorted(c.value for c in self.categories),
            "hits": [
                {"category": h.category.value, "label": h.label,
                 "weight": h.weight, "field": h.field_path}
                for h in self.hits
            ],
        }


def _walk_strings(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Yield (dotted_path, string_value) for every string in a nested structure."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, str):
        out.append((prefix or "<root>", obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_walk_strings(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_walk_strings(v, f"{prefix}[{i}]"))
    return out


class ThreatScanner:
    """Scans tool-call arguments for known-dangerous content shapes."""

    def __init__(self, max_excerpt: int = 60) -> None:
        self.max_excerpt = max_excerpt

    def scan(self, arguments: dict[str, Any]) -> ScanResult:
        hits: list[ThreatHit] = []
        for path, value in _walk_strings(arguments or {}):
            for pattern, category, label, weight in _PATTERNS:
                m = pattern.search(value)
                if m:
                    start = max(0, m.start() - 10)
                    excerpt = value[start:start + self.max_excerpt]
                    hits.append(ThreatHit(category=category, label=label,
                                          weight=weight, field_path=path,
                                          excerpt=excerpt))
        score = sum(h.weight for h in hits)
        cats = frozenset(h.category for h in hits)
        return ScanResult(hits=tuple(hits), score=score, categories=cats)
