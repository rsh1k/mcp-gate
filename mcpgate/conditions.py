"""Conditions: a small, SAFE predicate language over tool-call arguments.

Policies need to say things like "amount under 500" or "path starts with /tmp".
The unsafe way to do that is eval() on a string — which would hand arbitrary
code execution to whoever writes policy, defeating the entire purpose. Instead
this module defines a tiny declarative condition tree built from plain
dicts/lists in the policy file. There is NO code execution anywhere here.

Condition forms (as they appear under a rule's `when:` key):

  {"field": "amount", "op": "lt", "value": 500}
  {"field": "path", "op": "startswith", "value": "/etc"}
  {"all": [ {...}, {...} ]}          # logical AND
  {"any": [ {...}, {...} ]}          # logical OR
  {"not": {...}}                     # negation

`field` is a dotted path into the call arguments, e.g. "filters.region".
Supported ops: eq ne lt le gt ge in not_in contains startswith endswith
               regex exists

# HARDENING: the regex op compiles user-supplied patterns. A pathological
# pattern can cause ReDoS. Before production, compile with a timeout (e.g. the
# `regex` module's timeout arg) or restrict regex to an allowlist of patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .errors import PolicyError  # noqa: F401


class _ConditionError(Exception):
    pass


def _resolve(path: str, args: dict[str, Any]) -> tuple[bool, Any]:
    """Resolve a dotted path. Returns (found, value)."""
    cur: Any = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


class Condition:
    """Base condition. Subclasses implement evaluate()."""

    def evaluate(self, args: dict[str, Any]) -> bool:  # pragma: no cover
        raise NotImplementedError


@dataclass(frozen=True)
class AlwaysTrue(Condition):
    def evaluate(self, args: dict[str, Any]) -> bool:
        return True


@dataclass(frozen=True)
class Comparison(Condition):
    field: str
    op: str
    value: Any = None

    def evaluate(self, args: dict[str, Any]) -> bool:
        found, actual = _resolve(self.field, args)

        if self.op == "exists":
            return found
        if not found:
            # A missing field can never satisfy a value comparison. This is a
            # deliberate fail-safe: absent data does not accidentally match.
            return False

        op = self.op
        v = self.value
        try:
            if op == "eq":
                return actual == v
            if op == "ne":
                return actual != v
            if op == "lt":
                return _num(actual) < _num(v)
            if op == "le":
                return _num(actual) <= _num(v)
            if op == "gt":
                return _num(actual) > _num(v)
            if op == "ge":
                return _num(actual) >= _num(v)
            if op == "in":
                return actual in v
            if op == "not_in":
                return actual not in v
            if op == "contains":
                return v in actual
            if op == "startswith":
                return str(actual).startswith(str(v))
            if op == "endswith":
                return str(actual).endswith(str(v))
            if op == "regex":
                return re.search(str(v), str(actual)) is not None
        except (TypeError, ValueError):
            # Type mismatch (e.g. lt on a string) => condition simply fails.
            # It does NOT crash the proxy. Failing the condition is safer than
            # failing the request open.
            return False

        raise _ConditionError(f"unknown op: {op}")


def _num(x: Any) -> float:
    if isinstance(x, bool):  # bool is a subclass of int; reject to avoid surprises
        raise ValueError("bool not comparable as number")
    return float(x)


@dataclass(frozen=True)
class And(Condition):
    parts: tuple[Condition, ...]

    def evaluate(self, args: dict[str, Any]) -> bool:
        return all(p.evaluate(args) for p in self.parts)


@dataclass(frozen=True)
class Or(Condition):
    parts: tuple[Condition, ...]

    def evaluate(self, args: dict[str, Any]) -> bool:
        return any(p.evaluate(args) for p in self.parts)


@dataclass(frozen=True)
class Not(Condition):
    inner: Condition

    def evaluate(self, args: dict[str, Any]) -> bool:
        return not self.inner.evaluate(args)


_VALID_OPS = {
    "eq", "ne", "lt", "le", "gt", "ge", "in", "not_in",
    "contains", "startswith", "endswith", "regex", "exists",
}


def parse_condition(raw: Any) -> Condition:
    """Build a Condition tree from plain data. Raises PolicyError on bad input."""
    from .errors import PolicyError as PE

    if raw is None:
        return AlwaysTrue()
    if not isinstance(raw, dict):
        raise PE(f"condition must be a mapping, got {type(raw).__name__}")

    if "all" in raw:
        return And(tuple(parse_condition(p) for p in raw["all"]))
    if "any" in raw:
        return Or(tuple(parse_condition(p) for p in raw["any"]))
    if "not" in raw:
        return Not(parse_condition(raw["not"]))

    if "field" in raw and "op" in raw:
        op = raw["op"]
        if op not in _VALID_OPS:
            raise PE(f"unknown condition op {op!r}; valid: {sorted(_VALID_OPS)}")
        return Comparison(field=str(raw["field"]), op=op, value=raw.get("value"))

    raise PE(f"unrecognized condition shape: {raw!r}")
