# Show HN draft

Hacker News rewards plain, specific, non-marketing language and honesty about
limitations. Below: title options, the post body, and prepared answers for the
comments that always come.

---

## Title options (pick one, ≤ 80 chars)

1. `Show HN: mcp-gate – a policy firewall for AI agent tool calls (MIT)`
2. `Show HN: Runtime governance proxy for MCP tool calls, mapped to NIST/OWASP`
3. `Show HN: mcp-gate – intercept, allow/deny/redact every AI-agent tool call`

Option 1 is the safest: concrete, names the analogy people already understand
(firewall), states the license.

---

## Post body

I built mcp-gate, an open-source proxy that sits between an AI agent and its
tools and enforces a policy on every tool call. It speaks the Model Context
Protocol (MCP), so it works with anything that does — Claude Code, Gemini CLI,
CrewAI, custom agents — without per-framework glue.

The problem I kept running into: teams have decent controls on *which model* an
agent uses, but almost nothing on *what the agent actually does* once it starts
calling tools. A tool call that issues a refund, writes a file, or hits an
external API is usually trusted by default — no per-call policy, no risk
scoring, no audit trail. That's the layer mcp-gate governs.

For each `tools/call` it intercepts, it returns one of four decisions:

- allow
- deny (the agent gets a clean JSON-RPC error)
- require human approval (held until someone says yes)
- redact (forward the call but mask named argument fields, e.g. strip a bcc)

Policies are plain YAML, reviewed in a PR like Terraform. They're argument-aware
and stateful — you can write "support agents may refund under $500 each, capped
at $2000 per session," and the per-session budget is enforced across calls. The
condition language does not use eval; it's a small declarative tree, so policy
authors can't execute code.

Every decision is written to an append-only, SHA-256 hash-chained audit log.
`mcp-gate verify` re-walks the chain and detects any edit, reorder, or deletion.
There's also a heuristic scanner that flags prompt injection / secret exfil /
command injection in arguments and (by default) routes those to human approval
rather than silent denial.

I mapped the controls to the NIST AI RMF, the NIST NCCoE draft on AI agent
identity & authorization (Feb 2026), and the OWASP Agentic Top 10, and there's a
`report` command that turns the audit log into a compliance-evidence summary.

What it is NOT: a finished, certified, "zero false positives" product. A policy
engine's false-positive rate comes from the policies you write, not the engine —
so I focused on making it auditable and exhaustively testable instead of making
claims I can't back. The threat scanner is a heuristic, framed as
feeding-approval, not detection. Everything that still needs hardening is marked
with `# HARDENING:` comments in the source. It's stdio-transport only right now;
HTTP + OAuth is the next milestone.

Core is stdlib-only (zero runtime deps), MIT licensed. 37 unit tests + a
20-sample end-to-end harness (all green; the audit chain verifies over all 20).

Repo: https://github.com/rsh1k/mcp-gate
Install: `pip install mcp-gate`

Would love feedback on the policy model and the threat-scanner approach
specifically.

---

## Prepared answers for the comment section

**"How is this different from OPA / a normal API gateway?"**
Same idea, different layer. OPA evaluates a request you've already shaped into
its input model; mcp-gate understands MCP's `tools/call` natively, runs on the
agent's stdio pipe, and adds agent-specific things a generic gateway doesn't:
per-session budgets, agent identity as the principal, and argument redaction
keyed to tool semantics. You could back the decision engine with OPA — the
engine is a clean, swappable component.

**"Heuristic regex for prompt injection? That's trivially bypassed."**
Agreed, and the README says so. The heuristic is a cheap, deterministic,
network-free first pass that can't itself be prompt-injected. It's wired to
human approval, not denial, precisely because it has false negatives and
positives. The `ThreatScanner` interface is there so you can put a real
classifier behind it; the heuristic is the floor, not the ceiling.

**"Isn't the proxy a single point of failure / bottleneck?"**
The decision engine is pure and synchronous with no network calls, so it's fast.
Fail-open vs fail-closed is an explicit operator choice — you decide whether an
engine error blocks or forwards. For HA you'd run multiple instances; the one
caveat today is that session budgets use an in-memory store, so multi-replica
budget enforcement needs the Redis-backed store (a documented roadmap item).

**"Why would I trust security software some stranger posted?"**
You shouldn't, on my say-so. That's why it's MIT, dependency-free, small enough
to read in an afternoon, and shipped with its tests and an honest list of what
isn't done. Read it, run it, get it reviewed before it touches production.

**"Does it work with non-MCP agents?"**
Only via MCP today. The decision engine itself is transport-agnostic, so wrapping
another protocol means writing a new proxy front-end against the same Gate.

**"Compliance mapping feels like marketing."**
Fair concern. It's explicitly labeled a self-assessment aid, not a
certification — NIST AI RMF is voluntary and the NCCoE paper is a draft. The
value is the evidence trail (`report` reads the real audit log), not a
checkbox. If the mapping is wrong anywhere, that's a bug I want filed.

---

## Logistics

- Post Tue–Thu, ~8–10am US Eastern, for best visibility.
- Be in the thread to answer for the first 2–3 hours; engagement matters more
  than the title.
- Don't argue — concede real limitations fast (it builds trust) and file the
  good ones as issues live in the thread.
- Cross-post to r/LocalLLaMA, r/netsec (read their self-promo rules first), and
  the MCP contributor Discord, but stagger them; don't blast simultaneously.
