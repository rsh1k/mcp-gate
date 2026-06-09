"""Compliance mapping: how mcp-gate controls map to published frameworks.

This module exists so an enterprise security or GRC team can answer "which
controls does this satisfy, and where is the evidence?" without reverse-
engineering the code. It is grounded in real, current sources (2026):

  * NIST AI RMF 1.0 (NIST AI 100-1) — the Govern / Map / Measure / Manage
    functions. mcp-gate is a MANAGE-and-MEASURE control: it enforces and
    records risk decisions at runtime.
  * NIST AI 600-1 — Generative AI Profile (governs model content behavior;
    mcp-gate complements it by governing the agent's ACTION behavior).
  * NIST NCCoE concept paper, "Accelerating the Adoption of Software and AI
    Agent Identity and Authorization" (Feb 2026) — its four operational
    concerns: identification, authorization, auditing & non-repudiation, and
    prompt-injection mitigation. mcp-gate implements a control for each.
  * OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10).

IMPORTANT: This is a self-assessment AID, not a certification or legal opinion.
NIST AI RMF is voluntary and not certifiable; the NCCoE paper is a draft. Treat
the output as supporting evidence you map into your own control library and have
independently reviewed. Frameworks evolve — re-verify against the current
published versions before relying on any mapping.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ControlMapping:
    capability: str               # what mcp-gate does
    nist_rmf: tuple[str, ...]     # AI RMF function/subcategory references
    nccoe_pillar: str             # NCCoE agent identity/authz concern
    owasp_asi: tuple[str, ...]    # OWASP Agentic Top 10 IDs addressed
    evidence: str                 # where the evidence lives at runtime


# The mapping is data, not prose, so you can render it into whatever your GRC
# tooling consumes (CSV, the README table, an audit appendix).
CONTROL_MAP: tuple[ControlMapping, ...] = (
    ControlMapping(
        capability="Per-call policy decision on every tools/call",
        nist_rmf=("MANAGE 2.1 (risk treatment applied)",
                  "MEASURE 2.7 (security & resilience evaluated)"),
        nccoe_pillar="Authorization",
        owasp_asi=("ASI02 Tool Misuse & Exploitation",
                   "ASI01 Agent Goal Hijack"),
        evidence="Audit log: one record per decision with rule_id + reason",
    ),
    ControlMapping(
        capability="Per-agent cryptographic identity (not shared credentials)",
        nist_rmf=("GOVERN 1.2 (accountability structures)",
                  "MAP 1.1 (context & actors established)"),
        nccoe_pillar="Identification",
        owasp_asi=("ASI03 Agent Identity & Privilege Abuse",),
        evidence="Audit log: agent_id + roles attributed to each action",
    ),
    ControlMapping(
        capability="Hash-chained tamper-evident audit log with verify()",
        nist_rmf=("MEASURE 2.8 (transparency & accountability)",
                  "MANAGE 4.1 (post-deployment monitoring)"),
        nccoe_pillar="Auditing & Non-repudiation",
        owasp_asi=("ASI03 Agent Identity & Privilege Abuse",
                   "ASI10 Rogue Agents"),
        evidence="audit.jsonl chain + `mcp-gate verify` integrity check",
    ),
    ControlMapping(
        capability="Heuristic threat scan of tool-call arguments",
        nist_rmf=("MEASURE 2.6 (AI system is evaluated for safety)",
                  "MANAGE 2.2 (mechanisms to sustain AI risk reduction)"),
        nccoe_pillar="Prompt-injection mitigation",
        owasp_asi=("ASI01 Agent Goal Hijack",
                   "ASI02 Tool Misuse & Exploitation",
                   "ASI06 Memory & Context Poisoning"),
        evidence="Audit log: threat_scan obligation with category + score",
    ),
    ControlMapping(
        capability="Stateful per-session budgets / action ceilings",
        nist_rmf=("MANAGE 1.3 (risk response prioritized)",
                  "MANAGE 2.4 (mechanisms to limit harm)"),
        nccoe_pillar="Authorization",
        owasp_asi=("ASI08 Cascading Agent Failures",
                   "ASI02 Tool Misuse & Exploitation"),
        evidence="SessionStore totals + budget-driven rule fallthrough in audit",
    ),
    ControlMapping(
        capability="Human-in-the-loop approval effect",
        nist_rmf=("GOVERN 1.1 (human oversight)",
                  "MANAGE 2.3 (human review of high-risk actions)"),
        nccoe_pillar="Authorization",
        owasp_asi=("ASI09 Human-Agent Trust Exploitation",
                   "ASI08 Cascading Agent Failures"),
        evidence="Audit log: require_approval decisions + approval outcome",
    ),
    ControlMapping(
        capability="Fail-closed default + deny-by-default policy posture",
        nist_rmf=("GOVERN 1.2 (risk tolerance defined)",
                  "MANAGE 2.1 (treatment applied before action)"),
        nccoe_pillar="Authorization",
        owasp_asi=("ASI02 Tool Misuse & Exploitation",),
        evidence="Policy default_effect=deny; fail_mode=closed in config",
    ),
    ControlMapping(
        capability="Argument redaction before forwarding",
        nist_rmf=("MANAGE 2.4 (mechanisms to limit harm)",
                  "MEASURE 2.10 (privacy risk evaluated)"),
        nccoe_pillar="Authorization",
        owasp_asi=("ASI02 Tool Misuse & Exploitation",),
        evidence="Audit log: redact decisions; values masked on the wire",
    ),
)


def render_markdown_table() -> str:
    """Render CONTROL_MAP as a Markdown table for the README / audit appendix."""
    lines = [
        "| Capability | NIST AI RMF | NCCoE pillar | OWASP ASI | Evidence |",
        "|---|---|---|---|---|",
    ]
    for m in CONTROL_MAP:
        lines.append(
            f"| {m.capability} | {'; '.join(m.nist_rmf)} | {m.nccoe_pillar} "
            f"| {', '.join(m.owasp_asi)} | {m.evidence} |"
        )
    return "\n".join(lines)


def coverage_summary() -> dict[str, list[str]]:
    """Which OWASP ASI items and NCCoE pillars get at least one control."""
    asi: set[str] = set()
    pillars: set[str] = set()
    for m in CONTROL_MAP:
        asi.update(m.owasp_asi)
        pillars.add(m.nccoe_pillar)
    return {
        "owasp_asi_addressed": sorted(asi),
        "nccoe_pillars_addressed": sorted(pillars),
    }
