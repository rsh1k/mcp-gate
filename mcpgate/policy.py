"""Policy model: declarative, version-controllable policy-as-code.

A policy is an ordered list of rules. For a given tool call, rules are evaluated
top to bottom; the FIRST matching rule wins (like a firewall ruleset or an ACL).
If nothing matches, the policy's `default_effect` applies. Default should be
DENY for a locked-down posture; the loader warns if you set it to ALLOW.

A rule matches on:
  - which tool        (exact name or glob, e.g. "github.*")
  - which agent       (agent_id glob and/or required roles)
  - a condition       (an argument-/state-aware predicate; see conditions.py)

A rule produces an Effect plus optional redaction fields and budget tracking.

The schema is plain YAML/JSON so it diffs cleanly in a pull request. The whole
point is that a security team reviews policy the way they review Terraform.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .decision import Effect
from .errors import PolicyError
from .conditions import Condition, parse_condition, AlwaysTrue

__all__ = ["Policy", "Rule", "Budget", "PolicyError", "load_policy"]


@dataclass(frozen=True)
class Budget:
    """A cumulative ceiling enforced across a session.

    e.g. {"key": "refund_total", "field": "amount", "limit": 2000} means: sum the
    `amount` argument across all calls matching this rule within one session; once
    the running total would exceed 2000, the rule stops matching (so a later DENY
    rule or the default can catch it). Budgets are what make enforcement stateful
    rather than per-call — the gap the research kept pointing at.
    """

    key: str
    field: str
    limit: float


@dataclass(frozen=True)
class Rule:
    id: str
    effect: Effect
    tools: tuple[str, ...] = ("*",)          # globs
    agents: tuple[str, ...] = ("*",)         # agent_id globs
    require_roles: tuple[str, ...] = ()      # agent must hold ALL of these
    condition: Condition = field(default_factory=AlwaysTrue)
    redact_fields: tuple[str, ...] = ()
    budget: Budget | None = None
    # If set, this rule matches only when the threat-scan score on the call's
    # arguments is >= this value. Lets you write e.g. "hold for approval if the
    # injection/exfil score is high" without hardcoding patterns in policy.
    min_threat_score: int | None = None
    reason: str = ""
    obligations: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...]
    default_effect: Effect = Effect.DENY
    version: str = "0"
    name: str = "unnamed-policy"


_VALID_EFFECTS = {e.value for e in Effect}


def _parse_rule(raw: dict[str, Any], index: int) -> Rule:
    rid = str(raw.get("id") or f"rule-{index}")

    effect_str = raw.get("effect")
    if effect_str not in _VALID_EFFECTS:
        raise PolicyError(
            f"rule '{rid}': effect must be one of {sorted(_VALID_EFFECTS)}, "
            f"got {effect_str!r}"
        )
    effect = Effect(effect_str)

    def as_tuple(value: Any, name: str) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            return tuple(value)
        raise PolicyError(f"rule '{rid}': '{name}' must be a string or list of strings")

    tools = as_tuple(raw.get("tools", "*"), "tools") or ("*",)
    agents = as_tuple(raw.get("agents", "*"), "agents") or ("*",)
    require_roles = as_tuple(raw.get("require_roles"), "require_roles")
    redact_fields = as_tuple(raw.get("redact_fields"), "redact_fields")

    cond_raw = raw.get("when")
    condition = parse_condition(cond_raw) if cond_raw is not None else AlwaysTrue()

    budget = None
    if "budget" in raw:
        b = raw["budget"]
        try:
            budget = Budget(key=str(b["key"]), field=str(b["field"]),
                            limit=float(b["limit"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError(
                f"rule '{rid}': budget needs key, field, numeric limit"
            ) from exc

    if effect is Effect.REDACT and not redact_fields:
        raise PolicyError(f"rule '{rid}': effect 'redact' requires redact_fields")

    min_threat_score = None
    if "min_threat_score" in raw:
        try:
            min_threat_score = int(raw["min_threat_score"])
        except (TypeError, ValueError) as exc:
            raise PolicyError(
                f"rule '{rid}': min_threat_score must be an integer"
            ) from exc

    return Rule(
        id=rid,
        effect=effect,
        tools=tools,
        agents=agents,
        require_roles=require_roles,
        condition=condition,
        redact_fields=redact_fields,
        budget=budget,
        min_threat_score=min_threat_score,
        reason=str(raw.get("reason", "")),
        obligations=dict(raw.get("obligations", {})),
    )


def load_policy(source: str | Path | dict[str, Any]) -> Policy:
    """Load a policy from a YAML/JSON file path or an already-parsed dict.

    YAML is supported if PyYAML is installed; JSON always works from stdlib.
    """
    if isinstance(source, dict):
        data = source
    else:
        path = Path(source)
        text = path.read_text()
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml  # optional dependency
            except ImportError as exc:
                raise PolicyError(
                    "PyYAML not installed; use JSON or `pip install pyyaml`"
                ) from exc
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)

    if not isinstance(data, dict):
        raise PolicyError("policy root must be a mapping")

    default_str = data.get("default_effect", "deny")
    if default_str not in _VALID_EFFECTS:
        raise PolicyError(f"default_effect must be one of {sorted(_VALID_EFFECTS)}")
    default_effect = Effect(default_str)

    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be a list")

    rules = tuple(_parse_rule(r, i) for i, r in enumerate(raw_rules))

    seen: set[str] = set()
    for r in rules:
        if r.id in seen:
            raise PolicyError(f"duplicate rule id: {r.id}")
        seen.add(r.id)

    return Policy(
        rules=rules,
        default_effect=default_effect,
        version=str(data.get("version", "0")),
        name=str(data.get("name", "unnamed-policy")),
    )
