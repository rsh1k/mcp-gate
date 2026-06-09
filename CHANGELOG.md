# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
semantic versioning (pre-1.0: minor versions may include breaking changes).

## [0.3.0] - 2026-06-09

### Added
- **Asymmetric agent identity (Ed25519)** via a pluggable `IdentityVerifier`
  interface. `Ed25519Verifier` lets mcp-gate hold only the public key while the
  agent holds the private key — giving non-repudiation, the direction NIST's
  NCCoE agent-identity guidance points at (JWT-SVID / SPIFFE). Behind the
  optional `[crypto]` extra. `HmacVerifier` remains for dev/single-tenant.
- `mcp-gate keygen` and `mcp-gate token --scheme ed25519` CLI support;
  `mcp-gate run --pubkey <hex>` runs the proxy with asymmetric verification.
- Tokens now embed their signature scheme; verifiers refuse scheme downgrade.
- README sections explicitly framing the threat scanner as
  heuristic-feeding-approval (not detection) and HMAC vs Ed25519 identity.

### Changed
- Token format gained a scheme segment: `<payload>.<scheme>.<signature>`.
  The `issue_token` / `verify_token` convenience helpers still work (HMAC).

## [0.2.0] - 2026-06-09

### Added
- **Heuristic threat scanner** (`threats.py`): detects prompt injection, command
  injection, secret exfiltration, path traversal, and suspicious URLs in tool
  arguments. Explainable, deterministic, no network calls.
- **`min_threat_score`** rule field so policies can hold high-risk calls for
  human approval based on the scan score.
- **Compliance mapping** (`compliance.py`) to NIST AI RMF, the NIST NCCoE agent
  identity/authorization concept paper, and the OWASP Agentic Top 10.
- **Compliance evidence reports** (`report.py`) generated from the audit log,
  with an integrity attestation and per-agent non-repudiation summary.
- New CLI commands: `report` and `controls`.
- 20-sample labeled verification harness (`tests/test_samples.py`).
- Repo hygiene: `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, CI workflow.
- **Packaging & distribution**: multi-stage non-root `Dockerfile` + `.dockerignore`,
  `RELEASING.md` (PyPI + GHCR guide), a tag-triggered `release.yml` workflow
  (PyPI Trusted Publishing + GHCR), and a Show HN launch draft (`docs/show-hn.md`).
  Package validated with `twine check` (wheel + sdist PASSED).

### Changed
- License is **MIT**.
- Threat findings are now attached to audit records as a `threat_scan`
  obligation, even on allow decisions, for review.

## [0.1.0] - 2026-06-09

### Added
- Policy decision engine (first-match-wins), argument-aware + stateful conditions.
- Four enforcement effects: allow / deny / require_approval / redact.
- Per-agent cryptographic identity.
- Hash-chained, tamper-evident audit log with `verify()`.
- Fail-open / fail-closed posture.
- stdio MCP proxy and CLI (`check`, `verify`, `token`, `run`).
- 28-test unit suite.
