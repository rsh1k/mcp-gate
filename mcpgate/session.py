"""Session state: the memory that makes enforcement stateful.

Budgets ("no more than $2000 of refunds per session") require accumulating
values across calls. SessionState holds those running totals, keyed by the
budget key from the matching rule.

The default in-memory store is correct for a single proxy process. For a
horizontally-scaled deployment you need shared state.

# HARDENING: InMemorySessionStore is per-process and lost on restart. For multi-
# replica or durable enforcement, implement SessionStore against Redis or a
# database with atomic increment + compare. The interface is intentionally tiny
# so this swap is localized.
"""

from __future__ import annotations

import threading
from typing import Protocol


class SessionStore(Protocol):
    def get_total(self, session_id: str, budget_key: str) -> float: ...
    def would_exceed(self, session_id: str, budget_key: str,
                     add: float, limit: float) -> bool: ...
    def commit(self, session_id: str, budget_key: str, add: float) -> None: ...


class InMemorySessionStore:
    """Thread-safe in-process store. Good for a single proxy instance."""

    def __init__(self) -> None:
        self._totals: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def get_total(self, session_id: str, budget_key: str) -> float:
        with self._lock:
            return self._totals.get((session_id, budget_key), 0.0)

    def would_exceed(self, session_id: str, budget_key: str,
                     add: float, limit: float) -> bool:
        with self._lock:
            current = self._totals.get((session_id, budget_key), 0.0)
            return (current + add) > limit

    def commit(self, session_id: str, budget_key: str, add: float) -> None:
        # Only called AFTER a call is allowed and actually forwarded, so the
        # budget reflects real spend, not attempted spend.
        with self._lock:
            key = (session_id, budget_key)
            self._totals[key] = self._totals.get(key, 0.0) + add
