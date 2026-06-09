"""PolicyEngine: the Policy Decision Point.

Given a tool call (tool name, arguments), the calling agent's identity, and a
session id, the engine returns exactly one Decision. It is pure and
synchronous: no I/O, no network, no forwarding. That separation matters — the
engine is the part you can test exhaustively and reason about, while the messy
transport/forwarding lives in the proxy.

Evaluation order (first match wins, like a firewall):
  for each rule in policy order:
      if rule matches (tool glob, agent glob, roles, condition, budget):
          return that rule's decision
  return policy.default_effect
"""

from __future__ import annotations

import fnmatch
from typing import Any

from .decision import Decision, Effect
from .identity import AgentIdentity
from .policy import Policy, Rule
from .session import SessionStore, InMemorySessionStore
from .threats import ThreatScanner, ScanResult


class PolicyEngine:
    def __init__(self, policy: Policy, store: SessionStore | None = None,
                 scanner: ThreatScanner | None = None) -> None:
        self.policy = policy
        self.store = store or InMemorySessionStore()
        # The scanner is always available so rules can reference threat scores.
        self.scanner = scanner or ThreatScanner()

    # -- matching helpers -------------------------------------------------

    @staticmethod
    def _matches_any_glob(value: str, globs: tuple[str, ...]) -> bool:
        return any(fnmatch.fnmatchcase(value, g) for g in globs)

    def _rule_matches(self, rule: Rule, tool: str, args: dict[str, Any],
                      identity: AgentIdentity, session_id: str,
                      scan: ScanResult) -> bool:
        if not self._matches_any_glob(tool, rule.tools):
            return False
        if not self._matches_any_glob(identity.agent_id, rule.agents):
            return False
        if rule.require_roles and not all(
            identity.has_role(r) for r in rule.require_roles
        ):
            return False
        if rule.min_threat_score is not None and scan.score < rule.min_threat_score:
            return False
        if not rule.condition.evaluate(args):
            return False
        if rule.budget is not None:
            # Budget participates in MATCHING: once the running total would be
            # exceeded by this call, the rule stops matching, so evaluation
            # falls through to whatever rule/default handles the over-limit case
            # (typically a DENY). This keeps budget logic declarative.
            found, raw_val = _resolve(rule.budget.field, args)
            add = _safe_float(raw_val) if found else 0.0
            if self.store.would_exceed(session_id, rule.budget.key, add,
                                       rule.budget.limit):
                return False
        return True

    # -- public API -------------------------------------------------------

    def evaluate(self, tool: str, args: dict[str, Any],
                 identity: AgentIdentity, session_id: str) -> Decision:
        args = args or {}
        scan = self.scanner.scan(args)
        for rule in self.policy.rules:
            if self._rule_matches(rule, tool, args, identity, session_id, scan):
                obligations = dict(rule.obligations)
                if not scan.clean:
                    # Always surface threat findings in the audit trail, even on
                    # an allow, so analysts can review what slipped through.
                    obligations["threat_scan"] = scan.to_dict()
                return Decision(
                    effect=rule.effect,
                    rule_id=rule.id,
                    reason=rule.reason or f"matched rule {rule.id}",
                    redact_fields=rule.redact_fields,
                    obligations=obligations,
                )
        default_obligations: dict[str, Any] = {}
        if not scan.clean:
            default_obligations["threat_scan"] = scan.to_dict()
        return Decision(
            effect=self.policy.default_effect,
            rule_id="__default__",
            reason=f"no rule matched; default {self.policy.default_effect.value}",
            obligations=default_obligations,
        )

    def commit_budget(self, tool: str, args: dict[str, Any],
                      decision: Decision, session_id: str) -> None:
        """Record spend against a budget AFTER a call is forwarded.

        Looks up the rule that produced the decision; if it carries a budget,
        increments the running total. Called by the proxy only on successful
        forward, so budgets track real, completed actions.
        """
        if decision.rule_id == "__default__":
            return
        rule = next((r for r in self.policy.rules if r.id == decision.rule_id), None)
        if rule is None or rule.budget is None:
            return
        found, raw_val = _resolve(rule.budget.field, args or {})
        if found:
            self.store.commit(session_id, rule.budget.key, _safe_float(raw_val))


def _resolve(path: str, args: dict[str, Any]) -> tuple[bool, Any]:
    cur: Any = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def _safe_float(x: Any) -> float:
    try:
        if isinstance(x, bool):
            return 0.0
        return float(x)
    except (TypeError, ValueError):
        return 0.0
