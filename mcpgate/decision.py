"""Decision types: the vocabulary the engine speaks.

A policy evaluation always produces exactly one Decision. The four effects are
deliberately chosen to cover the real enforcement modes an enterprise needs:

  ALLOW          forward the call unchanged
  DENY           block the call; return a JSON-RPC error to the agent
  REQUIRE_APPROVAL  pause and ask a human; block until approved/denied
  REDACT         forward the call, but with named argument fields masked

Keeping this set small and explicit is intentional. Every code path that touches
enforcement must handle all four, so the type system forces completeness.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Effect(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REDACT = "redact"


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating one tool call against policy.

    `effect`        what to do with the call
    `rule_id`       which rule produced this decision (for audit + debugging)
    `reason`        human-readable explanation (shows up in audit + agent error)
    `redact_fields` for REDACT: dotted paths into the arguments to mask
    `obligations`   free-form metadata the enforcement layer may act on later
                    (e.g. {"notify": "secops-slack"}). Kept open on purpose so
                    you can extend behavior without changing this type.
    """

    effect: Effect
    rule_id: str
    reason: str
    redact_fields: tuple[str, ...] = ()
    obligations: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "redact_fields": list(self.redact_fields),
            "obligations": self.obligations,
        }
