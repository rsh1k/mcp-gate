# Security Policy

mcp-gate is security-critical software intended to sit on the tool-call path of
AI agents. We take vulnerabilities seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities. Instead, use
GitHub's private vulnerability reporting (Security tab → "Report a
vulnerability") or email the maintainer listed in the repository profile.

Include: a description, reproduction steps, affected version/commit, and impact.
We aim to acknowledge within 72 hours and to provide a remediation timeline
after triage.

## Scope and expectations

This project is published as a **foundation, not a hardened product**. Areas
known to require hardening before production use are marked inline with
`# HARDENING:` comments and summarized in the README roadmap. Reports about
those documented gaps are welcome but are treated as enhancements rather than
vulnerabilities unless they enable a concrete bypass beyond the documented
limitation.

Examples of in-scope issues:

- A tool call that should be denied by a correctly written policy is forwarded.
- The audit hash chain can be altered without `verify()` detecting it.
- The threat scanner or policy loader can be made to crash the proxy (DoS).
- The condition language can be made to execute code or escape its sandbox.

## Supported versions

Pre-1.0: only the latest released version receives fixes.
