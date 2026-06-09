"""Command-line interface for mcp-gate.

Subcommands:
  run       launch the stdio proxy in front of an upstream MCP server
  check     validate a policy file (catches errors before deploy)
  verify    verify the integrity of an audit log's hash chain
  token     mint an agent identity token (dev/testing convenience)

Example (wrapping a filesystem MCP server):
  mcp-gate run --policy policy.yaml --audit audit.jsonl --fail closed \\
      -- npx @modelcontextprotocol/server-filesystem /data
"""

from __future__ import annotations

import argparse
import logging
import sys

from .audit import AuditLog
from .enforce import FailMode
from .engine import PolicyEngine
from .errors import PolicyError
from .gate import Gate
from .identity import issue_token
from .policy import load_policy
from .stdio_proxy import StdioProxy


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    if policy.default_effect.value == "allow":
        print("WARNING: default_effect is 'allow' — this fails OPEN on unmatched "
              "calls. Prefer 'deny' for a locked-down posture.", file=sys.stderr)
    print(f"OK: '{policy.name}' v{policy.version}, {len(policy.rules)} rules, "
          f"default={policy.default_effect.value}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    ok, msg = AuditLog(args.audit).verify()
    print(("OK: " if ok else "TAMPER DETECTED: ") + msg,
          file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 2


def _cmd_report(args: argparse.Namespace) -> int:
    from .report import generate_report
    md = generate_report(args.audit)
    if args.out:
        from pathlib import Path
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"wrote compliance report to {args.out}")
    else:
        print(md)
    return 0


def _cmd_controls(args: argparse.Namespace) -> int:
    from .compliance import render_markdown_table, coverage_summary
    print(render_markdown_table())
    cov = coverage_summary()
    print("\nOWASP ASI addressed:", ", ".join(cov["owasp_asi_addressed"]))
    print("NCCoE pillars addressed:", ", ".join(cov["nccoe_pillars_addressed"]))
    return 0


def _cmd_token(args: argparse.Namespace) -> int:
    if args.scheme == "ed25519":
        from .identity import Ed25519Signer
        if not args.private_key:
            print("ed25519 tokens require --private-key (hex)", file=sys.stderr)
            return 1
        signer = Ed25519Signer(bytes.fromhex(args.private_key))
        print(signer.sign(args.agent_id, args.role or [], None))
    else:
        if not args.secret:
            print("hmac tokens require --secret", file=sys.stderr)
            return 1
        print(issue_token(args.secret.encode(), args.agent_id, args.role or [], None))
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Generate an Ed25519 keypair. Private key signs (lives with the agent);
    public key verifies (lives with mcp-gate)."""
    from .identity import Ed25519Signer
    try:
        signer = Ed25519Signer.generate()
    except Exception as exc:  # cryptography not installed
        print(f"keygen failed: {exc}", file=sys.stderr)
        return 1
    # Re-derive the private hex from a fresh generate is awkward; expose via API.
    from cryptography.hazmat.primitives import serialization
    priv_hex = signer._priv.private_bytes(  # noqa: SLF001 - intentional, CLI only
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    print(f"private_key_hex (keep secret, give to the agent): {priv_hex}")
    print(f"public_key_hex  (give to mcp-gate --pubkey):       {signer.public_key_hex()}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"refusing to start: invalid policy: {exc}", file=sys.stderr)
        return 1

    engine = PolicyEngine(policy)
    audit = AuditLog(args.audit)
    gate = Gate(engine, audit, fail_mode=FailMode(args.fail))

    verifier = None
    secret = None
    if args.pubkey:
        from .identity import Ed25519Verifier
        try:
            verifier = Ed25519Verifier.from_public_hex(args.pubkey)
        except Exception as exc:
            print(f"refusing to start: bad ed25519 pubkey: {exc}", file=sys.stderr)
            return 1
    elif args.secret:
        secret = args.secret.encode()

    proxy = StdioProxy(gate, args.upstream, identity_secret=secret,
                       verifier=verifier, session_id=args.session)
    return proxy.run()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-gate",
                                description="Runtime policy proxy for MCP tool calls")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("check", help="validate a policy file")
    pc.add_argument("--policy", required=True)
    pc.set_defaults(func=_cmd_check)

    pv = sub.add_parser("verify", help="verify audit log integrity")
    pv.add_argument("--audit", required=True)
    pv.set_defaults(func=_cmd_verify)

    prep = sub.add_parser("report", help="generate a compliance evidence report")
    prep.add_argument("--audit", required=True)
    prep.add_argument("--out", help="write Markdown here (default: stdout)")
    prep.set_defaults(func=_cmd_report)

    pctl = sub.add_parser("controls", help="print the NIST/OWASP control mapping")
    pctl.set_defaults(func=_cmd_controls)

    pt = sub.add_parser("token", help="mint an agent identity token")
    pt.add_argument("--scheme", choices=["hmac", "ed25519"], default="hmac")
    pt.add_argument("--secret", help="HMAC secret (for --scheme hmac)")
    pt.add_argument("--private-key", help="Ed25519 private key hex (for --scheme ed25519)")
    pt.add_argument("--agent-id", required=True)
    pt.add_argument("--role", action="append", help="repeatable")
    pt.set_defaults(func=_cmd_token)

    pk = sub.add_parser("keygen", help="generate an Ed25519 keypair (needs [crypto])")
    pk.set_defaults(func=_cmd_keygen)

    pr = sub.add_parser("run", help="run the stdio proxy")
    pr.add_argument("--policy", required=True)
    pr.add_argument("--audit", required=True)
    pr.add_argument("--fail", choices=["open", "closed"], default="closed")
    pr.add_argument("--secret", help="identity HMAC secret (symmetric; dev)")
    pr.add_argument("--pubkey", help="Ed25519 public key hex (asymmetric; recommended)")
    pr.add_argument("--session", default="stdio-session")
    pr.add_argument("upstream", nargs=argparse.REMAINDER,
                    help="-- then the upstream server command")
    pr.set_defaults(func=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    # Strip a leading "--" from REMAINDER for the run command.
    if getattr(args, "upstream", None) and args.upstream and args.upstream[0] == "--":
        args.upstream = args.upstream[1:]
    if getattr(args, "command", None) == "run" and not args.upstream:
        parser.error("run requires an upstream command after --")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
