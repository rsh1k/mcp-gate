#!/usr/bin/env python3
"""Bump the version in pyproject.toml.

Dependency-free on purpose: this runs in CI before anything is installed, and a
release tool that needs its own install step is a release tool that breaks on the
day you need it.

    python scripts/bump_version.py patch    # 0.1.0 -> 0.1.1
    python scripts/bump_version.py minor    # 0.1.4 -> 0.2.0
    python scripts/bump_version.py major    # 0.2.7 -> 1.0.0
    python scripts/bump_version.py --show   # print the current version

Prints the new version to stdout so a workflow can capture it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

# Anchored to the [project] table's own version key. A loose search would happily
# match a pinned dependency's version and rewrite that instead.
_VERSION_RE = re.compile(
    r'(?P<prefix>^\[project\](?:.*?\n)*?version\s*=\s*")(?P<version>[^"]+)(?P<suffix>")',
    re.MULTILINE,
)

LEVELS = ("major", "minor", "patch")


def read_version(text: str) -> tuple[str, re.Match[str]]:
    m = _VERSION_RE.search(text)
    if m is None:
        raise SystemExit("could not find a version under [project] in pyproject.toml")
    return m.group("version"), m


def bump(version: str, level: str) -> str:
    parts = version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise SystemExit(
            f"version {version!r} is not a plain major.minor.patch; bump it by hand"
        )
    major, minor, patch = (int(p) for p in parts)
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def main(argv: list[str]) -> int:
    text = PYPROJECT.read_text()
    current, match = read_version(text)

    if not argv or argv[0] in ("--show", "-s"):
        print(current)
        return 0

    level = argv[0]
    if level not in LEVELS:
        raise SystemExit(f"level must be one of {LEVELS}, got {level!r}")

    new = bump(current, level)
    start, end = match.span("version")
    PYPROJECT.write_text(text[:start] + new + text[end:])
    print(new)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
