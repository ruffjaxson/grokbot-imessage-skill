#!/usr/bin/env python3
"""Create or update gate.json without ever printing the helper token.

The hardened installer runs this as root against the root-owned
<config-root>/gate.json. It always preserves (or creates) the
contact_ref_hmac_key. With --gate-url it also records the approval-gate
origin and reads the helper token from stdin, so the token never appears in
argv, the environment, or the terminal. The file is replaced atomically and
is never readable by group/other, even briefly.

  printf '%s\\n' "$TOKEN" | sudo python3 -I tools/configure_gate.py \\
      --gate-json "$GATE_JSON" --gate-url https://gate.example.ts.net --token-stdin
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

PLACEHOLDER_KEY = "REPLACE_ON_INSTALL"
MAX_GATE_JSON_BYTES = 16 * 1024


def _load_gate_client():
    path = Path(__file__).resolve().parent.parent / "bin" / "gate_client.py"
    spec = importlib.util.spec_from_file_location("gate_client", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_existing(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {}
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"refusing: {path} is not a regular file")
    if metadata.st_size > MAX_GATE_JSON_BYTES:
        raise SystemExit(f"refusing: {path} is unexpectedly large")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"refusing: {path} is not valid JSON: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"refusing: {path} root must be an object")
    return data


def merge(
    existing: dict[str, Any],
    *,
    gate_url: str | None,
    token: str | None,
    disable: bool,
) -> dict[str, Any]:
    gate_client = _load_gate_client()
    data = dict(existing)
    data.setdefault("schema_version", 1)
    key = data.get("contact_ref_hmac_key")
    if not isinstance(key, str) or not key.strip() or key == PLACEHOLDER_KEY:
        data["contact_ref_hmac_key"] = secrets.token_urlsafe(32)
    if disable:
        data.pop("gate_url", None)
        data.pop("helper_token", None)
    elif gate_url is not None:
        try:
            data["gate_url"] = gate_client.validate_gate_url(gate_url)
            data["helper_token"] = gate_client.validate_helper_token(token)
        except gate_client.GateConfigError as exc:
            raise SystemExit(f"refusing: {exc}")
    return data


def write_atomic(path: Path, data: dict[str, Any]) -> None:
    directory = path.parent
    tmp = directory / f".{path.name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gate-json", required=True, type=Path)
    parser.add_argument("--gate-url", help="approval gate origin, e.g. https://host.ts.net")
    parser.add_argument("--token-stdin", action="store_true", help="read the helper token from stdin")
    parser.add_argument("--disable", action="store_true", help="remove the gate section")
    args = parser.parse_args(argv)

    if args.disable and args.gate_url:
        parser.error("--disable and --gate-url are mutually exclusive")
    if bool(args.gate_url) != bool(args.token_stdin):
        parser.error("--gate-url requires --token-stdin (and vice versa)")

    token = None
    if args.token_stdin:
        token = sys.stdin.readline().strip()
        if not token:
            parser.error("no helper token on stdin")

    existing = read_existing(args.gate_json)
    data = merge(existing, gate_url=args.gate_url, token=token, disable=args.disable)
    write_atomic(args.gate_json, data)

    if data.get("gate_url"):
        changed = "updated" if args.gate_url else "unchanged"
        print(f"gate.json: approval gate {data['gate_url']} (helper token {changed})", file=sys.stderr)
    else:
        print("gate.json: no approval gate configured (legacy local policy)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
