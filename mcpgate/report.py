"""Report: turn the audit log into a compliance-evidence summary.

The same enforcement stream that blocks bad calls is the evidence an auditor
asks for. This module reads an audit log and produces:

  * decision counts by effect (allow/deny/approval/redact)
  * per-agent activity (non-repudiation: who did what, how often)
  * threat findings rolled up by category
  * a chain-integrity attestation (the log is internally tamper-evident)
  * the control-to-framework mapping (NIST AI RMF / NCCoE / OWASP)

Output is a Markdown report suitable for an audit appendix. It intentionally
reports only what the log proves; it makes no compliance CLAIM beyond "these
controls operated and here is the record."
"""

from __future__ import annotations

import datetime as _dt
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .compliance import render_markdown_table, coverage_summary


def _iso(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat()


def generate_report(audit_path: str | Path) -> str:
    log = AuditLog(audit_path)
    records: list[dict[str, Any]] = list(log)

    effect_counts: Counter[str] = Counter()
    agent_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    threat_cats: Counter[str] = Counter()
    threat_events = 0
    first_ts = last_ts = None

    for r in records:
        effect_counts[r["decision"]["effect"]] += 1
        agent_counts[r["agent_id"]] += 1
        rule_counts[r["decision"]["rule_id"]] += 1
        obl = r["decision"].get("obligations", {})
        scan = obl.get("threat_scan")
        if scan:
            threat_events += 1
            for c in scan.get("categories", []):
                threat_cats[c] += 1
        ts = r["timestamp"]
        first_ts = ts if first_ts is None else min(first_ts, ts)
        last_ts = ts if last_ts is None else max(last_ts, ts)

    chain_ok, chain_msg = log.verify()
    cov = coverage_summary()

    out: list[str] = []
    out.append("# mcp-gate Compliance Evidence Report")
    out.append("")
    out.append(f"_Generated {_iso(_dt.datetime.now(_dt.timezone.utc).timestamp())}_")
    out.append("")
    out.append("> This report summarizes runtime governance evidence captured by "
               "mcp-gate. It is a self-assessment aid, not a certification. NIST "
               "AI RMF is voluntary; the NCCoE agent-identity paper is a draft. "
               "Have an independent reviewer validate before relying on it.")
    out.append("")

    out.append("## 1. Audit integrity attestation")
    out.append("")
    status = "PASS — chain intact" if chain_ok else "FAIL — TAMPER DETECTED"
    out.append(f"- Integrity check: **{status}** ({chain_msg})")
    out.append(f"- Records: **{len(records)}**")
    if first_ts and last_ts:
        out.append(f"- Window: {_iso(first_ts)} → {_iso(last_ts)}")
    out.append("")

    out.append("## 2. Decisions by effect")
    out.append("")
    out.append("| Effect | Count |")
    out.append("|---|---|")
    for eff in ("allow", "deny", "require_approval", "redact"):
        out.append(f"| {eff} | {effect_counts.get(eff, 0)} |")
    out.append("")

    out.append("## 3. Activity by agent (non-repudiation)")
    out.append("")
    out.append("| Agent | Actions |")
    out.append("|---|---|")
    for agent, n in agent_counts.most_common():
        out.append(f"| `{agent}` | {n} |")
    out.append("")

    out.append("## 4. Threat findings")
    out.append("")
    if threat_events == 0:
        out.append("No threat-scan findings recorded in this window.")
    else:
        out.append(f"Tool calls with threat findings: **{threat_events}**")
        out.append("")
        out.append("| Category | Calls flagged |")
        out.append("|---|---|")
        for cat, n in threat_cats.most_common():
            out.append(f"| {cat} | {n} |")
    out.append("")

    out.append("## 5. Most-fired rules")
    out.append("")
    out.append("| Rule | Times applied |")
    out.append("|---|---|")
    for rule, n in rule_counts.most_common(10):
        out.append(f"| `{rule}` | {n} |")
    out.append("")

    out.append("## 6. Control-to-framework mapping")
    out.append("")
    out.append(render_markdown_table())
    out.append("")
    out.append("### Coverage summary")
    out.append("")
    out.append("- OWASP Agentic Top 10 addressed: "
               + ", ".join(cov["owasp_asi_addressed"]))
    out.append("- NCCoE agent-identity pillars addressed: "
               + ", ".join(cov["nccoe_pillars_addressed"]))
    out.append("")

    return "\n".join(out)
