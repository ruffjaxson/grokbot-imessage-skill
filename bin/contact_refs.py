"""Opaque contact references for agent-facing responses.

contact_ref values are HMAC-SHA256 digests of normalized handles, keyed by a
secret in root-owned gate.json. The helper resolves refs back to sendable
handles internally; agents receive name, service, and label — not raw numbers.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any


class ContactRefError(Exception):
    """Raised when gate config or contact_ref resolution fails."""


def contact_service(normalized: str) -> str:
    """Messaging service label for a normalized handle."""
    return "email" if "@" in normalized else "iMessage"


def _gate_path() -> Path:
    override = os.environ.get("IMESSAGE_GATE_PATH", "").strip()
    if override:
        return Path(os.path.abspath(os.path.expanduser(override)))
    bridge = os.environ.get("IMESSAGE_BRIDGE_DIR") or os.environ.get(
        "COWORK_IMESSAGE_BRIDGE_DIR", ""
    )
    if bridge:
        return Path(os.path.abspath(os.path.expanduser(bridge))) / "contacts" / "gate.json"
    raise ContactRefError("IMESSAGE_GATE_PATH or IMESSAGE_BRIDGE_DIR is required")


def _require_root_gate() -> bool:
    return (
        os.environ.get("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY") == "1"
        or "IMESSAGE_PRODUCT_ID" in os.environ
    )


def _validate_gate_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ContactRefError(f"gate config not found: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ContactRefError(f"gate config must be a regular file: {path}")
    if _require_root_gate():
        if metadata.st_uid != 0:
            raise ContactRefError(f"gate config must be root-owned: {path}")
        if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ContactRefError(f"gate config has group/world permissions: {path}")
    else:
        if metadata.st_uid != os.getuid():
            raise ContactRefError(f"gate config must be owned by the current user: {path}")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ContactRefError(
                f"gate config must not be group/world-writable: {path}"
            )


def load_gate_config() -> dict[str, Any]:
    path = _gate_path()
    _validate_gate_file(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContactRefError(f"gate config unreadable: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ContactRefError("gate config root must be an object")
    return data


def _hmac_key() -> bytes:
    config = load_gate_config()
    raw = config.get("contact_ref_hmac_key")
    if not isinstance(raw, str) or not raw.strip():
        raise ContactRefError("gate config missing contact_ref_hmac_key")
    return raw.strip().encode("utf-8")


def make_contact_ref(normalized: str, key: bytes | None = None) -> str:
    digest = hmac.new(
        key if key is not None else _hmac_key(),
        normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest


def resolve_contact_ref(
    contact_ref: str,
    contacts: dict[str, str],
    *,
    key: bytes | None = None,
) -> str:
    """Map an opaque contact_ref back to its normalized handle key."""
    if not isinstance(contact_ref, str) or not contact_ref.strip():
        raise ValueError("contact_ref must be a non-empty string")
    ref = contact_ref.strip()
    hkey = key if key is not None else _hmac_key()
    for normalized in contacts:
        if hmac.compare_digest(make_contact_ref(normalized, hkey), ref):
            return normalized
    raise ValueError("unknown contact_ref")


def lookup_match(
    normalized: str,
    name: str,
    label: str,
    *,
    key: bytes | None = None,
) -> dict[str, str]:
    return {
        "name": name,
        "service": contact_service(normalized),
        "label": label,
        "contact_ref": make_contact_ref(normalized, key),
    }


def generate_gate_config() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contact_ref_hmac_key": secrets.token_urlsafe(32),
    }
