#!/usr/bin/env python3
"""Lint installer scripts for hardcoded privileged-tool paths."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_PATHS = (
    REPO_ROOT / "install-hardened.sh",
    REPO_ROOT / "uninstall-hardened.sh",
    REPO_ROOT / "tools" / "configure_allowlist.py",
)
BANNED_LITERALS = (
    "/usr/bin/chown",
    "sudo /usr/bin/chown",
    '"/usr/bin/chown"',
)
HARDCODED_SUDO_RE = re.compile(
    r"""sudo\s+/(?:usr/bin|bin|sbin)/[A-Za-z0-9._-]+"""
)


def main() -> int:
    failures: list[str] = []
    for path in SCAN_PATHS:
        if not path.is_file():
            failures.append(f"missing scan target: {path}")
            continue
        text = path.read_text(encoding="utf-8")
        for banned in BANNED_LITERALS:
            if banned in text:
                failures.append(f"{path}: contains banned literal {banned!r}")
        for match in HARDCODED_SUDO_RE.finditer(text):
            failures.append(
                f"{path}: hardcoded sudo tool path {match.group(0)!r}; "
                "use tools/privileged_tools.sh or _privileged_tool()"
            )

    privileged_tools = REPO_ROOT / "tools" / "privileged_tools.sh"
    if not privileged_tools.is_file():
        failures.append(f"missing helper: {privileged_tools}")
    else:
        text = privileged_tools.read_text(encoding="utf-8")
        if "load_privileged_tool_paths" not in text:
            failures.append(f"{privileged_tools}: missing load_privileged_tool_paths")

    if failures:
        print("privileged-path check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("privileged-path check OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
