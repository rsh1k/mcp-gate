# Milestone: HTTP / Streamable transport + OAuth identity

Status: **design sketch / not yet implemented.** This is the top roadmap item
and a good first major contribution. It explains how the existing,
transport-agnostic core extends to MCP's HTTP transport without touching the
decision logic.

## Why this is the next milestone

The core today ships a **stdio** proxy only. stdio is the right first target
(local agents, subprocess model, no auth between client and server per the MCP
spec), but production agent fleets increasingly use the **streamable HTTP**
transport, where MCP authorization is **OAuth 2.1** (PKCE, resource indicators,
protected-resource metadata). To govern those deployments, mcp-gate needs an
HTTP front-end.

The good news: the `Gate` (enforcement point) and `PolicyEngine` (decision
point) are already transport-agnostic and pure. **None of that code changes.**
This milestone is a new front-end plus an OAuth-based `IdentityVerifier`.

## Architecture

```
MCP client ──HTTP(S)──▶  mcp-gate HTTP proxy  ──HTTP(S)──▶  upstream MCP server
   (Bearer token)            │  (new)                          (protected resource)
                             ▼
                     existing Gate + PolicyEngine (unchanged)
```

The HTTP proxy:

1. Terminates the client's HTTP/streamable connection.
2. Extracts the agent identity from the `Authorization: Bearer <jwt>` header.
3. Parses the JSON-RPC body. For `tools/call`, runs `Gate.handle_request(...)`
   exactly as the stdio proxy does.
4. On allow/redact, forwards (the redacted) request upstream and streams the
   response back. On deny/approval-reject, returns the JSON-RPC error directly
   and never contacts upstream.

## Work breakdown

### 1. `JwtSvidVerifier` (new `IdentityVerifier`)
- Validate a JWT bearer token: signature against the issuer's JWKS, `exp`/`iat`,
  `aud` (must match this resource per RFC 8707 resource indicators), and `iss`
  (validate per RFC 9207 — the MCP 2026 spec hardened this against mix-up
  attacks in single-client/many-server deployments).
- Map JWT claims → `AgentIdentity` (`sub` → `agent_id`, a roles/scope claim →
  `roles`). This slots into the **existing** verifier interface; the Gate is
  unaffected.
- Deps: a vetted JWT/JWKS library (e.g. `pyjwt[crypto]` or `joserfc`) behind a
  new optional extra, e.g. `[http]`.

### 2. `HttpProxy` front-end
- Use a small ASGI app (the stdlib has no HTTP server suitable for this; pick a
  minimal, well-audited framework — keep it an extra, not a core dep).
- Implement the MCP streamable-HTTP semantics: POST for requests, the
  server-push/streaming channel for responses, session handling.
- Honor `tools/call` interception; pass every other method through untouched
  (same rule as stdio: gate actions, not handshake/discovery).

### 3. Token passthrough rule (security-critical)
- MCP forbids token passthrough: if mcp-gate or the upstream needs to call a
  *further* upstream API, it must use a token minted for that audience, never
  relay the client's token. Enforce this in the proxy: strip/scope the inbound
  token; do not forward it verbatim.

### 4. Protected Resource Metadata
- Serve `/.well-known/oauth-protected-resource` and return a `WWW-Authenticate`
  header on 401 pointing at it (RFC 9728), so standard MCP clients can discover
  how to authenticate to the gate.

### 5. Tests
- Mirror the stdio coverage: an HTTP equivalent of the 20-sample harness, plus
  JWT validation tests (expired, wrong audience, wrong issuer, bad signature,
  scheme/alg confusion) and a token-passthrough-refusal test.

## Explicit non-goals for this milestone
- No change to the policy language, engine, audit log, threat scanner, or
  compliance mapping. If a PR touches those, it's a different milestone.
- No bundled OAuth *server* — mcp-gate is a resource-side enforcement point and
  validates tokens from your existing IdP (Entra, Auth0, Okta, Keycloak, …).

## Acceptance criteria
- `mcp-gate run --http :8080 --pubkey-jwks <url> -- <upstream-url>` gates a real
  streamable-HTTP MCP server.
- The same policy file works unchanged across stdio and HTTP.
- JWT validation rejects expired/wrong-aud/wrong-iss/bad-sig tokens, and token
  passthrough is provably refused.
- All existing tests still pass; new HTTP tests added.

Pick this up by opening an issue referencing this doc so design discussion has a
home before code lands.
