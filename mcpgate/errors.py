"""Shared exception types, isolated to avoid circular imports between
policy.py and conditions.py."""


class PolicyError(Exception):
    """Raised when a policy file is malformed or semantically invalid."""
