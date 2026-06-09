"""Agent identity: agents as first-class security principals.

The research is blunt about this: most orgs run agents on shared service
accounts or borrowed human credentials, which destroys accountability. mcp-gate
assigns each agent a distinct principal so every decision in the audit log is
attributable to a specific agent, not a human standing in for it.

Identity verification is PLUGGABLE via the `IdentityVerifier` interface. Two
verifiers ship in the box:

  HmacVerifier      stdlib-only, symmetric (shared secret). Fine for a single-
                    tenant self-host and for dev/test. Does NOT give
                    non-repudiation: anyone who can verify can also forge,
                    because the same secret signs and checks.

  Ed25519Verifier   asymmetric. The signer holds a private key; mcp-gate holds
                    only the PUBLIC key, so the proxy can verify but cannot
                    forge. This is the production-appropriate choice and the
                    direction NIST's NCCoE agent-identity work points at (JWT-
                    SVID / SPIFFE use asymmetric signatures). Requires the
                    optional `cryptography` dependency: `pip install mcp-gate[crypto]`.

Token format (both verifiers): "<payload_hex>.<scheme>.<signature_hex>" where
scheme is "hmac-sha256" or "ed25519". Embedding the scheme lets a deployment
reject a downgrade (e.g. refuse hmac tokens when it expects ed25519).

# HARDENING:
#  - HmacVerifier is symmetric; for multi-tenant or zero-trust, use
#    Ed25519Verifier (or integrate a real SPIFFE/SPIRE workload API and verify
#    x509-SVID / JWT-SVID).
#  - Bind tokens to the transport to stop replay/relay (cf. MCP SEP-1932 DPoP /
#    SEP-1933 Workload Identity Federation). This module verifies the token's
#    authenticity and freshness, not its channel binding.
#  - Rotate keys; honor `issued_at` staleness; keep `max_age_seconds` short.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Protocol


class IdentityError(Exception):
    pass


@dataclass(frozen=True)
class AgentIdentity:
    """A verified agent principal.

    `agent_id`  stable unique id for this agent (used in policy matching)
    `roles`     roles granted to the agent (e.g. "support-agent")
    `issued_at` unix seconds; used for staleness checks
    `claims`    any additional verified attributes
    """

    agent_id: str
    roles: frozenset[str]
    issued_at: float
    claims: dict[str, str]

    @staticmethod
    def anonymous() -> "AgentIdentity":
        """Fallback principal for unauthenticated calls.

        Policies can (and in a locked-down deployment, should) deny anything
        attributed to 'anonymous'. Failing closed on identity is a policy choice,
        not a hardcoded one, so the engine stays flexible.
        """
        return AgentIdentity(
            agent_id="anonymous",
            roles=frozenset(),
            issued_at=time.time(),
            claims={},
        )

    def has_role(self, role: str) -> bool:
        return role in self.roles


# --------------------------------------------------------------------------
# Token (de)serialization shared by all verifiers
# --------------------------------------------------------------------------

def _encode_payload(agent_id: str, roles: list[str],
                    claims: dict[str, str] | None) -> bytes:
    payload = {
        "agent_id": agent_id,
        "roles": sorted(roles),
        "issued_at": time.time(),
        "claims": claims or {},
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


def _split_token(token: str) -> tuple[bytes, str, str]:
    """Return (raw_payload_bytes, scheme, signature_hex)."""
    try:
        raw_hex, scheme, sig = token.split(".", 2)
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise IdentityError("malformed identity token") from exc
    return raw, scheme, sig


def _payload_to_identity(raw: bytes, max_age_seconds: float | None) -> AgentIdentity:
    payload = json.loads(raw.decode())
    if max_age_seconds is not None:
        age = time.time() - float(payload["issued_at"])
        if age > max_age_seconds:
            raise IdentityError(f"identity token expired ({age:.0f}s old)")
    return AgentIdentity(
        agent_id=str(payload["agent_id"]),
        roles=frozenset(payload.get("roles", [])),
        issued_at=float(payload["issued_at"]),
        claims=dict(payload.get("claims", {})),
    )


# --------------------------------------------------------------------------
# Verifier interface + implementations
# --------------------------------------------------------------------------

class IdentityVerifier(Protocol):
    scheme: str
    def verify(self, token: str,
               max_age_seconds: float | None = None) -> AgentIdentity: ...


class HmacVerifier:
    """Symmetric HMAC-SHA256 verifier. stdlib-only. Dev / single-tenant."""

    scheme = "hmac-sha256"

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise IdentityError("HMAC secret must be non-empty")
        self._secret = secret

    def sign(self, agent_id: str, roles: list[str],
             claims: dict[str, str] | None = None) -> str:
        raw = _encode_payload(agent_id, roles, claims)
        sig = hmac.new(self._secret, raw, hashlib.sha256).hexdigest()
        return f"{raw.hex()}.{self.scheme}.{sig}"

    def verify(self, token: str,
               max_age_seconds: float | None = None) -> AgentIdentity:
        raw, scheme, sig = _split_token(token)
        if scheme != self.scheme:
            raise IdentityError(
                f"expected scheme {self.scheme}, got {scheme} (downgrade refused)")
        expected = hmac.new(self._secret, raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):  # constant-time
            raise IdentityError("identity token signature mismatch")
        return _payload_to_identity(raw, max_age_seconds)


class Ed25519Verifier:
    """Asymmetric Ed25519 verifier. Proxy holds only the PUBLIC key.

    Requires the optional `cryptography` dependency. Construct from a 32-byte
    raw public key, or use `from_public_pem` / `from_public_hex`.
    """

    scheme = "ed25519"

    def __init__(self, public_key_bytes: bytes) -> None:
        pub = self._load_public(public_key_bytes)
        self._pub = pub

    @staticmethod
    def _crypto():
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.exceptions import InvalidSignature
            return ed25519, InvalidSignature
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise IdentityError(
                "Ed25519 identity requires the 'cryptography' package; "
                "install with: pip install mcp-gate[crypto]") from exc

    @classmethod
    def _load_public(cls, raw: bytes):
        ed25519, _ = cls._crypto()
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)

    @classmethod
    def from_public_hex(cls, hex_str: str) -> "Ed25519Verifier":
        return cls(bytes.fromhex(hex_str))

    def verify(self, token: str,
               max_age_seconds: float | None = None) -> AgentIdentity:
        _, InvalidSignature = self._crypto()
        raw, scheme, sig = _split_token(token)
        if scheme != self.scheme:
            raise IdentityError(
                f"expected scheme {self.scheme}, got {scheme} (downgrade refused)")
        try:
            self._pub.verify(bytes.fromhex(sig), raw)
        except (InvalidSignature, ValueError) as exc:
            raise IdentityError("ed25519 signature verification failed") from exc
        return _payload_to_identity(raw, max_age_seconds)


class Ed25519Signer:
    """Holds a PRIVATE key to mint tokens. Lives with the agent, NOT the proxy.

    Provided so you can issue tokens and run the asymmetric path end-to-end.
    Keep private keys off the mcp-gate host.
    """

    scheme = "ed25519"

    def __init__(self, private_key_bytes: bytes) -> None:
        ed25519, _ = Ed25519Verifier._crypto()
        self._priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        ed25519, _ = Ed25519Verifier._crypto()
        from cryptography.hazmat.primitives import serialization
        key = ed25519.Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cls(raw)

    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization
        pub = self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub.hex()

    def sign(self, agent_id: str, roles: list[str],
             claims: dict[str, str] | None = None) -> str:
        raw = _encode_payload(agent_id, roles, claims)
        sig = self._priv.sign(raw).hex()
        return f"{raw.hex()}.{self.scheme}.{sig}"


# --------------------------------------------------------------------------
# Backward-compatible convenience functions (HMAC), used by CLI/tests
# --------------------------------------------------------------------------

def issue_token(secret: bytes, agent_id: str, roles: list[str],
                claims: dict[str, str] | None = None) -> str:
    """Mint an HMAC-signed identity token. Convenience wrapper."""
    return HmacVerifier(secret).sign(agent_id, roles, claims)


def verify_token(secret: bytes, token: str,
                 max_age_seconds: float | None = None) -> AgentIdentity:
    """Verify an HMAC-signed token. Convenience wrapper."""
    return HmacVerifier(secret).verify(token, max_age_seconds)
