#!/usr/bin/env python3
"""Grok Bot iMessage helper

Runs on macOS, triggered by launchd when a new file lands in control/requests/.
Scans the request queue, dispatches each whitelisted action against a snapshot
of ~/Library/Messages/chat.db, writes a response JSON into control/responses/,
and deletes the request.

Security posture:
  - Actions are strictly whitelisted (no eval/exec/shell-out).
  - All SQL uses parameterized queries.
  - chat.db is snapshotted to an in-memory database using SQLite's backup API.
  - Read policy is applied before any message text is returned.
  - 2FA codes, card numbers, and SSN patterns are redacted in responses.
  - Response writes are atomic (tmp + rename) so the agent never reads a
    half-written file.

This script should be invoked only by the signed `grokbot-imessage-helper`
wrapper. Running it directly still works but without the environment
hardening the wrapper provides.
"""

from __future__ import annotations

import fcntl
import glob
import hmac
import json
import os
import re
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import traceback
import uuid
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
CODE_ROOT = Path(__file__).resolve().parent.parent
if "IMESSAGE_BRIDGE_DIR" in os.environ:
    _bridge_root_value = os.environ["IMESSAGE_BRIDGE_DIR"]
elif "COWORK_IMESSAGE_BRIDGE_DIR" in os.environ:
    _bridge_root_value = os.environ["COWORK_IMESSAGE_BRIDGE_DIR"]
else:
    _bridge_root_value = str(CODE_ROOT)
if not _bridge_root_value:
    raise RuntimeError(
        "IMESSAGE_BRIDGE_DIR is required "
        "(COWORK_IMESSAGE_BRIDGE_DIR remains a one-release compatibility alias)"
    )
BRIDGE_ROOT = Path(
    os.path.abspath(os.path.expanduser(_bridge_root_value))
)
POLICY_ROOT = Path(
    os.path.abspath(
        os.path.expanduser(
            os.environ.get("IMESSAGE_POLICY_DIR")
            or str(BRIDGE_ROOT / "contacts")
        )
    )
)
REQUESTS_DIR = BRIDGE_ROOT / "control" / "requests"
RESPONSES_DIR = BRIDGE_ROOT / "control" / "responses"
LOG_PATH = BRIDGE_ROOT / "control" / "log.txt"
BLOCKLIST_PATH = POLICY_ROOT / "blocked_chats.txt"
ALLOWLIST_PATH = Path(
    os.path.abspath(
        os.path.expanduser(
            os.environ.get("COWORK_IMESSAGE_READ_ALLOWLIST")
            or str(
                POLICY_ROOT / "allowed_chats.txt"
            )
        )
    )
)
READ_POLICY_PATH = POLICY_ROOT / "read_policy.txt"
SEND_POLICY_PATH = POLICY_ROOT / "send_policy.json"
SEND_GATE_PATH = Path(
    os.path.abspath(
        os.path.expanduser(
            os.environ.get("IMESSAGE_SEND_GATE_PATH")
            or str(CODE_ROOT / "bin" / "send_gate.py")
        )
    )
)
CONTACT_REFS_PATH = Path(
    os.path.abspath(
        os.path.expanduser(
            os.environ.get("IMESSAGE_CONTACT_REFS_PATH")
            or str(CODE_ROOT / "bin" / "contact_refs.py")
        )
    )
)
GATE_CLIENT_PATH = Path(
    os.path.abspath(
        os.path.expanduser(
            os.environ.get("IMESSAGE_GATE_CLIENT_PATH")
            or str(CODE_ROOT / "bin" / "gate_client.py")
        )
    )
)
CONFIRM_HELPER_PATH = Path(
    os.path.abspath(
        os.path.expanduser(
            os.environ.get("IMESSAGE_CONFIRM_HELPER_PATH")
            or str(CODE_ROOT / "bin" / "grokbot-imessage-confirm")
        )
    )
)
WATCH_STATE_PATH = BRIDGE_ROOT / "state" / "watch.json"
GROK_ADDED_PATH = BRIDGE_ROOT / "state" / "grok_added.json"
CHAT_DB_PATH = Path.home() / "Library" / "Messages" / "chat.db"
HOST_DISPLAY_NAME = os.environ.get("IMESSAGE_HOST_DISPLAY_NAME", "Grok Bot")
PRODUCT_ID = os.environ.get("IMESSAGE_PRODUCT_ID", "grokbot-imessage")

# Detect wrapper mode: product if any IMESSAGE_* product vars set, else baked
_PRODUCT_ENV_VARS = (
    "IMESSAGE_PRODUCT_ID",
    "IMESSAGE_POLICY_DIR",
    "IMESSAGE_SEND_GATE_PATH",
    "IMESSAGE_CONFIRM_HELPER_PATH",
)
WRAPPER_MODE = "product" if any(v in os.environ for v in _PRODUCT_ENV_VARS) else "baked"

HELPER_VERSION = "1.4.8"
PROTOCOL_VERSION = "1.3"

# Bridge role. The DIY install and every host bridge run as "host". A
# management bridge (product mode, IMESSAGE_BRIDGE_ROLE=manager) is the only
# place `list_chats` is served, and it never serves body-returning actions.
# The table below is enforced in the worker; hiding an action in a host or
# app layer is not sufficient. Unknown role values fail closed.
_BRIDGE_ROLE_ENV = "IMESSAGE_BRIDGE_ROLE"
DEFAULT_BRIDGE_ROLE = "host"
_HOST_ACTIONS = (
    "status",
    "review",
    "search",
    "chat_history",
    "response_stats",
    "contacts_lookup",
    "send_preview",
    "send",
    "send_commit",
    "request_grant",
    "approval_status",
    "list_grants",
    "revoke_grant",
    "inbox",
    "watch_tick",
    "save_contact",
)
_MANAGER_ACTIONS = ("status", "contacts_lookup", "list_chats")
ROLE_ACTIONS: dict[str, tuple[str, ...]] = {
    "host": _HOST_ACTIONS,
    "manager": _MANAGER_ACTIONS,
}


def bridge_role() -> str:
    """Return the configured bridge role (unvalidated; see allowed_actions)."""
    value = os.environ.get(_BRIDGE_ROLE_ENV, "")
    return value.strip().lower() or DEFAULT_BRIDGE_ROLE


def allowed_actions(role: str | None = None) -> tuple[str, ...]:
    """Actions the worker will serve for `role`. Unknown roles get none."""
    return ROLE_ACTIONS.get(role if role is not None else bridge_role(), ())

# ---------------------------------------------------------------------------
# Sibling module loading
# ---------------------------------------------------------------------------
# The C wrapper runs python3 with `-I` (isolated mode), which deliberately
# prevents sys.path[0] from being set to this file's directory — it blocks
# the "drop a malicious foo.py into bin/ and watch helper.py import it"
# attack. We honor that hardening by loading our known-good sibling module
# by its absolute baked-in path rather than by ordinary import.
import importlib.util as _importlib_util  # noqa: E402


def _load_sibling(name: str):
    path = CODE_ROOT / "bin" / f"{name}.py"
    spec = _importlib_util.spec_from_file_location(name, path)
    mod = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_contact_refs():
    try:
        metadata = CONTACT_REFS_PATH.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(
                f"contact_refs must be a regular file: {CONTACT_REFS_PATH}"
            )
        if metadata.st_uid != 0 and metadata.st_uid != os.getuid():
            raise RuntimeError(
                f"contact_refs must be owned by root or current user: {CONTACT_REFS_PATH}"
            )
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError(
                f"contact_refs must not be group/world-writable: {CONTACT_REFS_PATH}"
            )
    except FileNotFoundError as exc:
        raise RuntimeError(f"contact_refs not found: {CONTACT_REFS_PATH}") from exc

    spec = _importlib_util.spec_from_file_location("contact_refs", CONTACT_REFS_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load contact_refs from {CONTACT_REFS_PATH}")
    mod = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_gate_client():
    """Loaded only when gate.json configures a gate, so legacy and product
    installs without gate_client.py are unaffected."""
    try:
        metadata = GATE_CLIENT_PATH.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"gate_client must be a regular file: {GATE_CLIENT_PATH}")
        if metadata.st_uid != 0 and metadata.st_uid != os.getuid():
            raise RuntimeError(
                f"gate_client must be owned by root or current user: {GATE_CLIENT_PATH}"
            )
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError(
                f"gate_client must not be group/world-writable: {GATE_CLIENT_PATH}"
            )
        if (
            os.environ.get("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY") == "1"
            and metadata.st_uid != 0
        ):
            raise RuntimeError(f"gate_client must be root-owned: {GATE_CLIENT_PATH}")
    except FileNotFoundError as exc:
        raise RuntimeError(f"gate_client not found: {GATE_CLIENT_PATH}") from exc

    spec = _importlib_util.spec_from_file_location("gate_client", GATE_CLIENT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load gate_client from {GATE_CLIENT_PATH}")
    mod = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_send_gate():
    # Item 3: defense-in-depth file validation
    # Wrapper validate_file is the trust boundary; this check adds depth.
    try:
        metadata = SEND_GATE_PATH.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"send_gate must be a regular file: {SEND_GATE_PATH}")
        # Root-owned or uid-owned both acceptable
        if metadata.st_uid != 0 and metadata.st_uid != os.getuid():
            raise RuntimeError(f"send_gate must be owned by root or current user: {SEND_GATE_PATH}")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError(f"send_gate must not be group/world-writable: {SEND_GATE_PATH}")
    except FileNotFoundError as exc:
        raise RuntimeError(f"send_gate not found: {SEND_GATE_PATH}") from exc
    
    spec = _importlib_util.spec_from_file_location("send_gate", SEND_GATE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load send_gate from {SEND_GATE_PATH}")
    mod = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Route send_gate's state to the bridge so the send gate knows where to write
# nonces. Preserve explicit values and retain the legacy name as a
# compatibility input. Empty explicit values have already failed closed above.
if "IMESSAGE_BRIDGE_DIR" not in os.environ and "COWORK_IMESSAGE_BRIDGE_DIR" not in os.environ:
    os.environ["IMESSAGE_BRIDGE_DIR"] = str(BRIDGE_ROOT)
_contact_refs = _load_contact_refs()
_send_gate = _load_send_gate()
SEND_NONCE_TTL = _send_gate.SEND_NONCE_TTL
SendGateError = _send_gate.SendGateError
mint_send_nonce = _send_gate.mint_send_nonce
consume_send_nonce = _send_gate.consume_send_nonce
reap_expired_nonces = _send_gate.reap_expired_nonces

APPLE_EPOCH = 978_307_200  # seconds between 1970-01-01 and 2001-01-01

# Parameter bounds. Over these limits we reject rather than return partial data.
MAX_DAYS = 90
MAX_HOURS = 24 * 30
MAX_LIMIT = 500
MAX_SEARCH_LEN = 200
# Snapshot size guard: in-memory snapshots exceeding this limit are rejected.
# Override with IMESSAGE_SNAPSHOT_MAX_MB. 1024 MB fits typical chat.db sizes
# while avoiding OOM on resource-constrained systems. Operators with larger
# databases should review memory availability before raising this limit.
DEFAULT_SNAPSHOT_MAX_MB = 1024
# list_chats has its own window: it returns no bodies, only which threads
# exist, so a multi-year window is safe and useful for policy discovery.
MAX_LIST_CHATS_DAYS = 3650
LIST_CHATS_DEFAULT_DAYS = 365
LIST_CHATS_DEFAULT_LIMIT = 200
LIST_CHATS_FILTER_SCAN_LIMIT = 500
MAX_LIST_CHATS_QUERY_LEN = 100
MAX_LIST_CHATS_PARTICIPANTS = 10
MAX_TEXT_SNIPPET = 600
MAX_CONTEXT_MESSAGES = 8
MAX_REQUEST_BYTES = 64 * 1024
RESPONSE_TTL_S = 60 * 60
LOG_MAX_BYTES = 1024 * 1024
LOG_BACKUP_COUNT = 3

# Send-side bounds. iMessage will accept much longer bodies, but capping here
# limits blast radius if a request is malformed or adversarial. 4000 chars is
# well above any plausible conversational message.
MAX_SEND_LEN = 4000
_SERVICE_ENUM = ("iMessage", "SMS")

# osascript timeout — the send itself is sub-second; anything much longer
# means Messages.app is hung or prompting for Automation permission.
OSASCRIPT_TIMEOUT_S = 15

import subprocess  # noqa: E402  — used only by send actions, keep the import local-ish


# ---------------------------------------------------------------------------
# Secure runtime filesystem access
# ---------------------------------------------------------------------------
_DIR_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_NOFOLLOW_FLAGS = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class UnsafeRuntimePath(RuntimeError):
    """Raised when user-owned bridge state is not a safe local file or directory."""


def _validate_private_directory(fd: int, label: str) -> None:
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode):
        raise UnsafeRuntimePath(f"{label} is not a directory")
    if metadata.st_uid != os.getuid():
        raise UnsafeRuntimePath(f"{label} is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise UnsafeRuntimePath(f"{label} must not have group/world permissions")


def _open_bridge_root() -> int:
    """Open the absolute bridge path one component at a time without symlinks."""
    root = Path(os.path.abspath(str(BRIDGE_ROOT)))
    if not root.is_absolute() or root == Path("/"):
        raise UnsafeRuntimePath("bridge root must be a non-root absolute path")

    fd = os.open("/", _DIR_OPEN_FLAGS)
    try:
        for component in root.parts[1:]:
            next_fd = os.open(component, _DIR_OPEN_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        _validate_private_directory(fd, f"bridge root {root}")
        return fd
    except UnsafeRuntimePath:
        os.close(fd)
        raise
    except OSError as exc:
        os.close(fd)
        raise UnsafeRuntimePath(f"unsafe bridge root {root}: {exc}") from exc


def _runtime_relative_parts(path: Path) -> tuple[str, ...]:
    root = Path(os.path.abspath(str(BRIDGE_ROOT)))
    candidate = Path(os.path.abspath(str(path)))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise UnsafeRuntimePath(f"runtime path escapes bridge root: {candidate}") from exc
    if any(part in ("", ".", "..") or "/" in part for part in relative.parts):
        raise UnsafeRuntimePath(f"invalid runtime path: {candidate}")
    return relative.parts


@contextmanager
def _private_directory_fd(path: Path, *, create: bool = False):
    """Yield an anchored descriptor for a private directory below the bridge."""
    parts = _runtime_relative_parts(path)
    fd = _open_bridge_root()
    try:
        for component in parts:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            try:
                next_fd = os.open(component, _DIR_OPEN_FLAGS, dir_fd=fd)
            except OSError as exc:
                raise UnsafeRuntimePath(f"unsafe runtime directory {path}: {exc}") from exc
            os.close(fd)
            fd = next_fd
            _validate_private_directory(fd, str(path))
        yield fd
    finally:
        os.close(fd)


def _validate_regular_file(fd: int, label: str, *, private: bool = False) -> os.stat_result:
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        raise UnsafeRuntimePath(f"{label} is not a regular file")
    if metadata.st_uid != os.getuid():
        raise UnsafeRuntimePath(f"{label} is not owned by the current user")
    if private and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise UnsafeRuntimePath(f"{label} must not have group/world permissions")
    return metadata


def _stat_regular_at(directory_fd: int, name: str, *, private: bool = False) -> os.stat_result:
    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise UnsafeRuntimePath(f"{name} is not a regular file")
    if metadata.st_uid != os.getuid():
        raise UnsafeRuntimePath(f"{name} is not owned by the current user")
    if private and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise UnsafeRuntimePath(f"{name} must not have group/world permissions")
    return metadata


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def _rotate_log(control_fd: int) -> None:
    try:
        current = _stat_regular_at(control_fd, LOG_PATH.name, private=True)
    except FileNotFoundError:
        return
    if current.st_size < LOG_MAX_BYTES:
        return

    oldest = f"{LOG_PATH.name}.{LOG_BACKUP_COUNT}"
    try:
        _stat_regular_at(control_fd, oldest, private=True)
    except FileNotFoundError:
        pass
    else:
        os.unlink(oldest, dir_fd=control_fd)

    for index in range(LOG_BACKUP_COUNT - 1, 0, -1):
        source = f"{LOG_PATH.name}.{index}"
        destination = f"{LOG_PATH.name}.{index + 1}"
        try:
            _stat_regular_at(control_fd, source, private=True)
        except FileNotFoundError:
            continue
        try:
            _stat_regular_at(control_fd, destination, private=True)
        except FileNotFoundError:
            pass
        os.replace(
            source,
            destination,
            src_dir_fd=control_fd,
            dst_dir_fd=control_fd,
        )

    os.replace(
        LOG_PATH.name,
        f"{LOG_PATH.name}.1",
        src_dir_fd=control_fd,
        dst_dir_fd=control_fd,
    )


def log(msg: str) -> None:
    """The log is user-readable, so phone numbers and emails are scrubbed."""
    try:
        msg = scrub_handles(msg)
        with _private_directory_fd(LOG_PATH.parent, create=True) as control_fd:
            _rotate_log(control_fd)
            fd = os.open(
                LOG_PATH.name,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | _FILE_NOFOLLOW_FLAGS,
                0o600,
                dir_fd=control_fd,
            )
            try:
                _validate_regular_file(fd, str(LOG_PATH), private=True)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    fd = -1
                    f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}\n")
            finally:
                if fd >= 0:
                    os.close(fd)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# attributedBody typedstream decoder (pure Python, no PyObjC)
# Ported from the original Perplexity skill and kept byte-compatible.
# ---------------------------------------------------------------------------
def _attributed_fail(data: bytes, reason: str) -> str:
    log(f"attributedBody parse failed: {reason}; bytes={len(data)}")
    return ""


def _attributed_string_at(data: bytes, idx: int) -> tuple[str, int] | None:
    p = idx + len(b"NSString") + 1

    while p < len(data) and data[p] in (0x84, 0x94, 0x85, 0x95, 0x01, 0x86):
        p += 1

    if p + 8 <= len(data) and data[p : p + 8] == b"NSObject":
        p += 8
        while p < len(data) and data[p] in (0x84, 0x94, 0x85, 0x95, 0x01, 0x86):
            p += 1

    if p < len(data) and data[p] == 0x2B:
        p += 1

    if p >= len(data):
        return None

    b0 = data[p]
    if b0 == 0x81:
        if p + 3 > len(data):
            return None
        length = struct.unpack("<H", data[p + 1 : p + 3])[0]
        p += 3
    elif b0 == 0x82:
        if p + 5 > len(data):
            return None
        length = struct.unpack("<I", data[p + 1 : p + 5])[0]
        p += 5
    elif b0 < 0x80:
        length = b0
        p += 1
    else:
        p += 1
        if p >= len(data):
            return None
        b0 = data[p]
        if b0 == 0x81:
            if p + 3 > len(data):
                return None
            length = struct.unpack("<H", data[p + 1 : p + 3])[0]
            p += 3
        elif b0 < 0x80:
            length = b0
            p += 1
        else:
            return None

    if length <= 0 or p + length > len(data):
        return None

    try:
        return data[p : p + length].decode("utf-8"), p + length
    except Exception:
        return None


def decode_attributed_body(blob: bytes | None) -> str:
    if not blob:
        return ""
    try:
        data = bytes(blob)
    except Exception:
        return ""
    if b"streamtyped" not in data[:16]:
        return ""

    if b"NSString" not in data:
        return ""

    candidates: list[str] = []
    expected_next: int | None = None
    search_from = 0
    while True:
        idx = data.find(b"NSString", search_from)
        if idx == -1:
            break
        parsed = _attributed_string_at(data, idx)
        if parsed is not None:
            text, end = parsed
            if expected_next is not None and idx > expected_next:
                break
            if text:
                candidates.append(text)
            expected_next = end
            search_from = max(idx + 1, end)
        else:
            search_from = idx + len(b"NSString")

    if not candidates:
        return _attributed_fail(data, "no decodable NSString payload")
    if len(candidates) == 1:
        return candidates[0]
    return "".join(candidates)


# ---------------------------------------------------------------------------
# Contacts (AddressBook sqlite)
#
# Keys in the returned dict are *normalized handles*:
#   - phone numbers: the last 10 digits (US-style; strips formatting)
#   - email addresses: lowercased, stripped
# Values are the display name for that contact. First+Last if present,
# otherwise the organization name (so "Café Vivant" still resolves even
# without a person attached).
# ---------------------------------------------------------------------------
_ADDRESSBOOK_PATTERNS = (
    "~/Library/Application Support/AddressBook/Sources/*/AddressBook-v22.abcddb",
    "~/Library/Application Support/AddressBook/AddressBook-v22.abcddb",
)


def _normalize_handle(h: str) -> str:
    """Produce the contacts-dict key for a handle string.

    Emails normalize to lowercase. Phones normalize to their last 10 digits.
    Anything shorter (short-codes) or unrecognized returns ''.
    """
    if not h:
        return ""
    s = h.strip()
    if "@" in s:
        return s.lower()
    digits = re.sub(r"[^0-9]", "", s)
    return digits[-10:] if len(digits) >= 10 else ""


_CONTACT_RAW_HANDLES: dict[str, str] = {}
_CONTACT_HANDLE_LABELS: dict[str, str] = {}
# Contacts keys whose AddressBook note carries GROK_ADDED_MARKER (save_contact).
_CONTACT_GROK_ADDED: set[str] = set()
GROK_ADDED_MARKER = "Added by Grok Bot (grokbot-imessage)"
GROK_CONTACTS_GROUP = "Added by Grok"


def _decode_addressbook_label(raw: str | None) -> str:
    """Normalize an AddressBook ZLABEL value to a short lowercase label."""
    if not raw or not str(raw).strip():
        return ""
    s = str(raw).strip()
    if s.startswith("_$!<") and s.endswith(">!$_"):
        s = s[4:-4]
    else:
        s = s.replace("_$!<", "").replace(">!$_", "")
    return s.strip().lower()


def contact_handle_label(normalized: str) -> str:
    """Return the AddressBook label for a normalized handle key."""
    return _CONTACT_HANDLE_LABELS.get(normalized, "")


def contact_raw_handle(normalized: str) -> str:
    """Return the sendable handle for a normalized contacts key."""
    return _CONTACT_RAW_HANDLES.get(normalized, normalized)


def load_contacts() -> dict[str, str]:
    """Return {normalized_handle: display_name}.

    Reads every AddressBook-v22.abcddb we can find (the local source + any
    CardDAV/iCloud sources). Loads phones, emails, and organizations. Logs
    how many handles were loaded so debugging doesn't require guessing.
    """
    global _CONTACT_RAW_HANDLES, _CONTACT_HANDLE_LABELS, _CONTACT_GROK_ADDED
    handle_to_name: dict[str, str] = {}
    raw_handles: dict[str, str] = {}
    handle_labels: dict[str, str] = {}
    grok_added: set[str] = set()
    owner_phone_count: dict[int, int] = {}
    owner_email_count: dict[int, int] = {}
    db_files: list[str] = []
    for pattern in _ADDRESSBOOK_PATTERNS:
        db_files.extend(glob.glob(os.path.expanduser(pattern)))
    if not db_files:
        log("contacts: no AddressBook-v22.abcddb files found "
            "(checked Sources/* and top-level)")
        return handle_to_name

    total_phones = 0
    total_emails = 0
    for p in db_files:
        try:
            # immutable=1 is a belt-and-suspenders: read-only *and* skip
            # locking, which avoids contending with Contacts.app.
            conn = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)
            cur = conn.cursor()

            # 1. Build Z_PK -> display name map. Person records get
            #    "First Last"; company records fall back to ZORGANIZATION.
            records: dict[int, str] = {}
            try:
                cur.execute(
                    "SELECT Z_PK, ZFIRSTNAME, ZLASTNAME, ZORGANIZATION "
                    "FROM ZABCDRECORD"
                )
            except sqlite3.Error:
                # Older schema may not have ZORGANIZATION — retry without it.
                cur.execute("SELECT Z_PK, ZFIRSTNAME, ZLASTNAME FROM ZABCDRECORD")
                for pk, fn, ln in cur.fetchall():
                    name = " ".join(x for x in (fn, ln) if x).strip()
                    if name:
                        records[pk] = name
            else:
                for pk, fn, ln, org in cur.fetchall():
                    name = " ".join(x for x in (fn, ln) if x).strip()
                    if not name and org:
                        name = org.strip()
                    if name:
                        records[pk] = name

            # Contacts created by save_contact carry a marker in their note.
            grok_owners: set[int] = set()
            try:
                cur.execute("SELECT ZCONTACT, ZTEXT FROM ZABCDNOTE")
                grok_owners = {
                    owner for owner, text in cur.fetchall() if text and GROK_ADDED_MARKER in str(text)
                }
            except sqlite3.Error:
                pass

            # 2. Phone numbers.
            try:
                try:
                    cur.execute(
                        "SELECT ZOWNER, ZFULLNUMBER, ZLABEL, ZORDERINGINDEX "
                        "FROM ZABCDPHONENUMBER "
                        "ORDER BY ZOWNER, ZORDERINGINDEX"
                    )
                    phone_rows = cur.fetchall()
                except sqlite3.Error:
                    cur.execute("SELECT ZOWNER, ZFULLNUMBER FROM ZABCDPHONENUMBER")
                    phone_rows = [(o, n, None, 0) for (o, n) in cur.fetchall()]
                for owner, num, zlabel, _ordering in phone_rows:
                    if owner not in records or not num:
                        continue
                    digits = re.sub(r"[^0-9]", "", num)
                    if len(digits) >= 10:
                        key = digits[-10:]
                        label = _decode_addressbook_label(zlabel)
                        if not label:
                            owner_phone_count[owner] = owner_phone_count.get(owner, 0) + 1
                            label = f"phone {owner_phone_count[owner]}"
                        if handle_to_name.setdefault(key, records[owner]) \
                                is records[owner]:
                            raw_handles.setdefault(key, num.strip())
                            handle_labels.setdefault(key, label)
                            if owner in grok_owners:
                                grok_added.add(key)
                            total_phones += 1
            except sqlite3.Error as e:
                log(f"contacts: phones table error on {p}: {e}")

            # 3. Email addresses. Prefer the normalized form, fall back to raw.
            try:
                cur.execute(
                    "SELECT ZOWNER, ZADDRESSNORMALIZED, ZADDRESS, ZLABEL, ZORDERINGINDEX "
                    "FROM ZABCDEMAILADDRESS "
                    "ORDER BY ZOWNER, ZORDERINGINDEX"
                )
                rows = cur.fetchall()
            except sqlite3.Error:
                # Older schema may not have ZADDRESSNORMALIZED.
                try:
                    cur.execute(
                        "SELECT ZOWNER, ZADDRESS, ZLABEL, ZORDERINGINDEX "
                        "FROM ZABCDEMAILADDRESS "
                        "ORDER BY ZOWNER, ZORDERINGINDEX"
                    )
                    rows = [(o, None, a, lbl, ord_idx) for (o, a, lbl, ord_idx) in cur.fetchall()]
                except sqlite3.Error:
                    try:
                        cur.execute("SELECT ZOWNER, ZADDRESS FROM ZABCDEMAILADDRESS")
                        rows = [(o, None, a, None, 0) for (o, a) in cur.fetchall()]
                    except sqlite3.Error as e:
                        log(f"contacts: emails table error on {p}: {e}")
                        rows = []
            for owner, norm, raw, zlabel, _ordering in rows:
                if owner not in records:
                    continue
                addr = (norm or raw or "").strip().lower()
                if addr and "@" in addr:
                    label = _decode_addressbook_label(zlabel)
                    if not label:
                        owner_email_count[owner] = owner_email_count.get(owner, 0) + 1
                        label = f"email {owner_email_count[owner]}"
                    if handle_to_name.setdefault(addr, records[owner]) \
                            is records[owner]:
                        raw_handles.setdefault(addr, addr)
                        handle_labels.setdefault(addr, label)
                        if owner in grok_owners:
                            grok_added.add(addr)
                        total_emails += 1

            conn.close()
        except Exception as e:
            log(f"contacts: warn on {p}: {e}")

    _CONTACT_RAW_HANDLES = raw_handles
    _CONTACT_HANDLE_LABELS = handle_labels
    _CONTACT_GROK_ADDED = grok_added
    log(f"contacts: loaded {len(handle_to_name)} handles "
        f"({total_phones} phones, {total_emails} emails) "
        f"from {len(db_files)} source(s)")
    return handle_to_name


def lookup_name(chat_id: str, sender: str, contacts: dict[str, str]) -> str:
    """Resolve the display name for a 1:1 chat or a message sender.

    Tries chat_id and sender in order — one of them is typically the
    canonical iMessage handle (phone or email).
    """
    for candidate in (chat_id, sender):
        key = _normalize_handle(candidate or "")
        if key:
            n = contacts.get(key)
            if n:
                return n
    return ""


def load_chat_participants(
    conn: sqlite3.Connection, chat_rowids: Iterable[int] | None = None
) -> dict[Any, list[str]]:
    """Return participant handles keyed by chat identifier or row ID.

    Used to build a human label for group chats whose chat_identifier is
    just "chatNNNNN…" and whose display_name is empty. With participants
    in hand we can render e.g. "Alice, Bob & 2 others" instead of the
    opaque group id. `chat_rowids` restricts the scan to candidate chats
    (bounded callers such as list_chats) and returns a ROWID-keyed map so
    duplicate chat_identifier rows cannot cross-contaminate participants.
    None keeps today's full scan and identifier-keyed map for review.
    """
    cur = conn.cursor()
    sql = """
        SELECT c.ROWID, c.chat_identifier, h.id
        FROM chat c
        JOIN chat_handle_join chj ON chj.chat_id = c.ROWID
        JOIN handle h ON h.ROWID = chj.handle_id
        """
    if chat_rowids is None:
        cur.execute(sql)
    else:
        ids = sorted({int(r) for r in chat_rowids})
        if not ids:
            return defaultdict(list)
        # SQLite's default variable limit is 999; chunk to stay under it.
        rows: list = []
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            cur.execute(sql + " WHERE c.ROWID IN (%s)" % ",".join("?" * len(chunk)), chunk)
            rows.extend(cur.fetchall())
        out: dict[str, list[str]] = defaultdict(list)
        for chat_rowid, _chat_ident, handle_id in rows:
            hi = handle_id.decode("utf-8", "ignore") if isinstance(handle_id, bytes) else (handle_id or "")
            if chat_rowid is not None and hi:
                out[int(chat_rowid)].append(hi)
        return out
    out: dict[str, list[str]] = defaultdict(list)
    for _chat_rowid, chat_ident, handle_id in cur.fetchall():
        ci = chat_ident.decode("utf-8", "ignore") if isinstance(chat_ident, bytes) else (chat_ident or "")
        hi = handle_id.decode("utf-8", "ignore") if isinstance(handle_id, bytes) else (handle_id or "")
        if ci and hi:
            out[ci].append(hi)
    return out


def group_label(
    participants: list[str], contacts: dict[str, str], *, reveal_unknown: bool = False
) -> str:
    """Render a friendly group-chat label from a list of handles.

    Uses first names when a contact resolves; falls back to the last 4
    digits of a phone ("…4567") or the raw email otherwise. Caps at 3
    named participants with "& N others" suffix so the label fits on
    one line in the review bucket.
    """
    if not participants:
        return ""
    parts: list[str] = []
    for h in participants:
        name = lookup_name(h, h, contacts)
        if name:
            parts.append(name.split()[0])  # first name only
        elif reveal_unknown:
            # Manager-only (list_chats policy discovery); host bridges stay anonymous.
            if "@" in (h or ""):
                parts.append(h)
            else:
                d = re.sub(r"[^0-9]", "", h or "")
                parts.append(f"…{d[-4:]}" if len(d) >= 4 else h)
        else:
            parts.append("Unknown")
    if len(parts) <= 3:
        return ", ".join(parts)
    return ", ".join(parts[:3]) + f" & {len(parts) - 3} others"


# ---------------------------------------------------------------------------
# Agent-facing identities
#
# Responses never carry raw phone numbers, email addresses, or chat
# identifiers. People appear as name + AddressBook label + contact_ref; group
# threads as a display name + thread_ref. Both refs are HMACs keyed by the
# root-owned gate.json secret, and the helper resolves them back internally.
# ---------------------------------------------------------------------------
_HANDLE_CANDIDATE_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|\+?\(?\d[\d\s().-]{5,}\d"
)
_DATE_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}(?::\d{2}){1,2})?")


def _redact_handle_match(m: re.Match) -> str:
    s = m.group(0)
    if "@" in s:
        return "[redacted]"
    if len(re.sub(r"\D", "", s)) < 7 or _DATE_TIME_RE.fullmatch(s.strip()):
        return s
    return "[redacted]"


def scrub_handles(text: str) -> str:
    """Remove phone numbers and email addresses from diagnostics (errors, logs)."""
    return _HANDLE_CANDIDATE_RE.sub(_redact_handle_match, text or "")


def thread_ref(chat_id: str) -> str:
    return _contact_refs.make_contact_ref("thread:" + chat_id)


def unknown_sender_name(key: str) -> str:
    """Last four digits help tell strangers apart; never the full number."""
    if "@" in key:
        return "Unknown sender (email)"
    return f"Unknown sender ···{key[-4:]}"


def person_view(handle: str, contacts: dict[str, str]) -> dict[str, Any]:
    key = _normalize_handle(handle or "")
    if not key:
        # Short codes and business senders: no stable personal identity.
        return {"name": "", "label": "automated sender" if handle else "", "contact_ref": None}
    known = key in contacts
    return {
        "name": contacts[key] if known else unknown_sender_name(key),
        "label": contact_handle_label(key) or ("email" if "@" in key else "phone"),
        "contact_ref": _contact_refs.make_contact_ref(key),
        "known": known,
    }


def thread_view(
    chat_id: str,
    sender: str,
    contacts: dict[str, str],
    *,
    display_name: str = "",
    participants: list[str] | None = None,
    style: Any = None,
) -> dict[str, Any]:
    if _chat_kind(chat_id or "", style) == "group":
        return {
            "is_group": True,
            "name": display_name or group_label(participants or [], contacts) or "Group chat",
            "label": "group",
            "contact_ref": None,
            "thread_ref": thread_ref(chat_id),
        }
    return {
        "is_group": False,
        **person_view(chat_id or sender, contacts),
        "thread_ref": thread_ref(chat_id) if chat_id else None,
    }


def message_view(
    m: dict[str, Any],
    contacts: dict[str, str],
    participants: dict[Any, list[str]] | None = None,
) -> dict[str, Any]:
    view = thread_view(
        m["chat_id"],
        m["sender"],
        contacts,
        display_name=m.get("display_name", ""),
        participants=(participants or {}).get(m["chat_id"]),
    )
    out = {
        **view,
        "ts": m["ts"],
        "is_from_me": m["is_from_me"],
        "text": redact(m["text"])[:MAX_TEXT_SNIPPET],
    }
    if view["is_group"] and not m["is_from_me"]:
        out["sender"] = person_view(m["sender"], contacts)
    return out


# ---------------------------------------------------------------------------
# Read privacy policy
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PrivacyPolicy:
    mode: str
    blocklist: tuple[str, ...]
    allowlist: tuple[str, ...]
    # "local": allowlist/blocklist files. "gate": grants from the approval gate,
    # where `allowlist` holds the read-scoped handles.
    source: str = "local"
    read: tuple[str, ...] = ()
    watch: tuple[str, ...] = ()
    send: tuple[str, ...] = ()
    grants: tuple[Any, ...] = field(default=(), compare=False, hash=False)
    gate_error: str | None = None
    # Canonical handle -> Apple-epoch ns history floor for read / watch grants
    # (None = no floor, i.e. lookback "all"). Reads never reach below it.
    read_since: dict[str, int | None] = field(default_factory=dict, compare=False, hash=False)
    watch_since: dict[str, int | None] = field(default_factory=dict, compare=False, hash=False)
    # Standing gate setting: read/watch 1:1 threads from numbers not in
    # Contacts, newer than unknown_floor (Apple-epoch ns).
    unknown_enabled: bool = False
    unknown_floor: int | None = None
    known_handles: frozenset = field(default_factory=frozenset, compare=False, hash=False)


GRANT_SCOPES = ("send", "read", "watch")
LOOKBACKS = ("grant_time", "7d", "30d", "all")
GATE_UNAVAILABLE_MESSAGE = "approval gate unavailable"


def canonical_handle(value: str) -> str | None:
    """E.164 or lowercased email, exactly as the gate stores it; None if the
    value can't be one (group ids, short codes, junk)."""
    if not value or value.strip().lower().startswith("chat"):
        return None
    try:
        return gate_handle(value)
    except ValueError:
        return None


def _grant_match(chat_id: str, handles: tuple[str, ...]) -> bool:
    """A per-contact grant covers only the 1:1 thread with that exact
    canonical handle. Group threads (chat ids like "chat123…") never match,
    even for messages the granted contact sent there: a group carries other
    people's messages and names. The last-10-digit matching in _matches_list
    is kept for the blocklist, where matching too much fails safe."""
    c = canonical_handle(chat_id)
    return c is not None and c in set(handles)


def _unknown_match(chat_id: str, policy: PrivacyPolicy) -> bool:
    """A 1:1 thread with a handle that isn't in Contacts, while the gate's
    unknown-senders setting is on."""
    if not policy.unknown_enabled or policy.unknown_floor is None:
        return False
    c = canonical_handle(chat_id)
    return c is not None and c not in policy.known_handles


def scoped_policy(policy: PrivacyPolicy | list[str], scope: str) -> PrivacyPolicy:
    """Gate mode: restrict reads to handles holding `scope`. Local mode: unchanged."""
    resolved = _coerce_policy(policy)
    if resolved.source != "gate":
        return resolved
    return replace(resolved, mode="allowlist", allowlist=getattr(resolved, scope))


def grant_scopes_for(handle: str, policy: PrivacyPolicy | list[str]) -> list[str]:
    """Scopes held by a contacts key (last-10 digits or email)."""
    resolved = _coerce_policy(policy)
    canonical = canonical_handle(contact_raw_handle(handle))
    return sorted(
        scope for scope in GRANT_SCOPES if canonical and canonical in getattr(resolved, scope)
    )


def history_floor_ok(chat_id: str, ts_ns: int, policy: PrivacyPolicy | list[str], scope: str) -> bool:
    """Gate mode: a read/watch message must be at or above that grant's
    history floor (lookback). Local mode: always True."""
    resolved = _coerce_policy(policy)
    if resolved.source != "gate":
        return True
    since = resolved.read_since if scope == "read" else resolved.watch_since
    c = canonical_handle(chat_id)
    if c is None:
        return False
    if c in since and (since[c] is None or ts_ns >= since[c]):
        return True
    return _unknown_match(chat_id, resolved) and ts_ns >= resolved.unknown_floor


def apply_scope(msgs: list[dict], policy: PrivacyPolicy | list[str], scope: str) -> list[dict]:
    """Read policy plus the scope's history floor."""
    return [
        m
        for m in apply_read_policy(msgs, policy)
        if history_floor_ok(m["chat_id"], m["ts_ns"], policy, scope)
    ]


_INVISIBLE_CONTROLS_RE = re.compile("[\u202a-\u202e\u2066-\u2069\u200b\u2060\ufeff]")


def sanitize_display_name(name: str) -> str:
    return _INVISIBLE_CONTROLS_RE.sub("", name or "").strip()


def _grok_added_registry() -> set[str]:
    data = _load_state_file(GROK_ADDED_PATH)
    handles = data.get("handles")
    return {h for h in handles if isinstance(h, str)} if isinstance(handles, list) else set()


def contact_origin(handle: str, contacts: dict[str, str]) -> str:
    """"unknown" (not in Contacts), "added_by_grok" (saved by save_contact:
    note marker or the helper's own record), or "contacts"."""
    key = _normalize_handle(handle)
    if not key or key not in contacts or canonical_handle(contact_raw_handle(key)) != handle:
        return "unknown"
    if key in _CONTACT_GROK_ADDED or handle in _grok_added_registry():
        return "added_by_grok"
    return "contacts"


def origin_is_honest(claimed: Any, handle: str, contacts: dict[str, str]) -> bool:
    """A Grok-added contact's approvals and grants must say so, because only
    then did the approval page warn that Grok chose the name."""
    return contact_origin(handle, contacts) != "added_by_grok" or claimed == "added_by_grok"


def expected_display_name(handle: str, contacts: dict[str, str]) -> str:
    """The name the helper itself would put on an approval for `handle`."""
    key = _normalize_handle(handle)
    if key and key in contacts and canonical_handle(contact_raw_handle(key)) == handle:
        name = sanitize_display_name(contacts[key])[:200]
        if name:
            return name
    return UNKNOWN_CONTACT_NAME


def _load_list(path: Path, require_root_owner: bool = False, require_uid_owner: bool = False) -> tuple[str, ...]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return ()
    if not stat.S_ISREG(metadata.st_mode):
        log(f"privacy policy rejected: {path} must be a regular file")
        return ()
    if require_root_owner:
        if metadata.st_uid != 0:
            log(f"privacy policy rejected: {path} must be root-owned")
            return ()
        if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            log(f"privacy policy rejected: {path} has group/world permissions")
            return ()
    if require_uid_owner:
        # Root-owned satisfies uid check (item 2: root/uid precedence)
        if metadata.st_uid == 0:
            if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                log(f"privacy policy rejected: {path} has group/world permissions")
                return ()
        elif metadata.st_uid != os.getuid():
            log(f"privacy policy rejected: {path} must be owned by the current user (uid {os.getuid()})")
            return ()
        elif metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            log(f"privacy policy rejected: {path} must not be group/world-writable")
            return ()
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return tuple(out)


@dataclass
class GateContext:
    """client is set when gate mode works; error is set when gate.json asks
    for a gate that can't be used. Either one means gate mode is on."""

    client: Any = None
    error: str | None = None
    module: Any = None

    @property
    def enabled(self) -> bool:
        return self.client is not None or self.error is not None

    @property
    def errors(self) -> tuple[type[BaseException], ...]:
        if self.module is None:
            return ()
        return (self.module.GateUnavailable, self.module.GateError)


_GATE_CONTEXT: GateContext | None = None


def _build_gate_context() -> GateContext:
    if bridge_role() == "manager":
        return GateContext()
    try:
        data = _contact_refs.load_gate_config()
    except _contact_refs.ContactRefError as exc:
        try:
            # A secrets pipe that fails to parse is as untrusted as a bad file.
            present = _contact_refs.secrets_via_fd() or os.path.lexists(_contact_refs._gate_path())
        except _contact_refs.ContactRefError:
            present = False
        if not present:
            log("gate: no gate.json; gate mode off")
            return GateContext()
        # A gate.json that exists but can't be trusted must never fall back
        # to the local allowlist.
        log(f"gate: gate.json rejected, failing closed: {exc}")
        return GateContext(error="gate.json unreadable or unsafe")
    if not data.get("gate_url") and not data.get("helper_token"):
        return GateContext()
    try:
        module = _load_gate_client()
        config = module.config_from_gate_json(data)
    except Exception as exc:
        log(f"gate: misconfigured, failing closed: {exc}")
        return GateContext(error=f"gate misconfigured: {exc}")
    return GateContext(client=module.GateClient(config), module=module)


def gate_context() -> GateContext:
    global _GATE_CONTEXT
    if _GATE_CONTEXT is None:
        _GATE_CONTEXT = _build_gate_context()
    return _GATE_CONTEXT


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _normalize_grants(raw: list[Any], contacts: dict[str, str]) -> tuple[dict[str, Any], ...]:
    """Keep only well-formed, unexpired grants whose handle is canonical and
    whose display name is the one the helper would have used. A grant created
    from a spoofed approval (e.g. "Mom" on someone else's number) is dropped."""
    now = datetime.now(timezone.utc)
    grants = []
    for g in raw:
        if not isinstance(g, dict):
            continue
        handle, scope, gid = g.get("handle"), g.get("scope"), g.get("id")
        if not isinstance(handle, str) or canonical_handle(handle) != handle:
            continue
        if scope not in GRANT_SCOPES or isinstance(gid, bool) or not isinstance(gid, int):
            continue
        created = _parse_iso(g.get("created_at"))
        if created is None:
            continue
        expires = g.get("expires_at")
        if expires is not None:
            parsed = _parse_iso(expires)
            if parsed is None or parsed <= now:
                continue
        display_name = str(g.get("display_name") or "")
        if display_name != expected_display_name(handle, contacts):
            log(f"gate: dropping grant {gid}: display name does not match local contacts")
            continue
        if not origin_is_honest(g.get("contact_origin"), handle, contacts):
            log(f"gate: dropping grant {gid}: approved without the added-by-Grok warning")
            continue
        lookback = g.get("lookback")
        if lookback not in (None, *LOOKBACKS):
            continue
        # lookback "all" = no floor. Otherwise use the gate's floor, falling
        # back to the grant's creation (the most conservative choice) when an
        # older gate doesn't send one.
        floor = None if lookback == "all" else (_parse_iso(g.get("history_floor_at")) or created)
        grants.append(
            {
                "id": gid,
                "handle": handle,
                "display_name": display_name,
                "scope": scope,
                "expires_at": expires,
                "created_at": created,
                "lookback": lookback or ("grant_time" if scope != "send" else None),
                "history_floor": floor,
            }
        )
    return tuple(grants)


def load_gate_policy(ctx: GateContext, contacts: dict[str, str] | None = None) -> PrivacyPolicy:
    """Fail closed: any gate problem yields a policy with no grants."""
    blocklist = _load_list(BLOCKLIST_PATH, require_uid_owner=WRAPPER_MODE == "product")
    closed = PrivacyPolicy(mode="allowlist", blocklist=blocklist, allowlist=(), source="gate")
    if ctx.error:
        return replace(closed, gate_error=ctx.error)
    try:
        data = ctx.client.policy()
    except ctx.errors as exc:
        log(f"gate: policy fetch failed, failing closed: {exc}")
        return replace(closed, gate_error=GATE_UNAVAILABLE_MESSAGE)
    contacts = load_contacts() if contacts is None else contacts
    grants = _normalize_grants(data["grants"], contacts)
    unknown = data.get("unknown_senders") if isinstance(data.get("unknown_senders"), dict) else {}
    unknown_floor_dt = _parse_iso(unknown.get("floor_at")) if unknown.get("enabled") is True else None
    known_handles = frozenset(
        c for c in (canonical_handle(contact_raw_handle(k)) for k in contacts) if c is not None
    )
    by_scope = {
        scope: tuple(g["handle"] for g in grants if g["scope"] == scope)
        for scope in GRANT_SCOPES
    }
    since: dict[str, dict[str, int | None]] = {"read": {}, "watch": {}}
    for g in grants:
        if g["scope"] not in since:
            continue
        floor = None if g["history_floor"] is None else to_apple_ns(g["history_floor"].timestamp())
        bucket = since[g["scope"]]
        if g["handle"] not in bucket:
            bucket[g["handle"]] = floor
        elif bucket[g["handle"]] is not None:
            # Several grants for one contact: the most generous floor wins.
            bucket[g["handle"]] = None if floor is None else min(floor, bucket[g["handle"]])
    return replace(
        closed,
        allowlist=by_scope["read"],
        read=by_scope["read"],
        watch=by_scope["watch"],
        send=by_scope["send"],
        grants=grants,
        read_since=since["read"],
        watch_since=since["watch"],
        unknown_enabled=unknown_floor_dt is not None,
        unknown_floor=to_apple_ns(unknown_floor_dt.timestamp()) if unknown_floor_dt else None,
        known_handles=known_handles,
    )


def load_privacy_policy() -> PrivacyPolicy:
    # Manager role: no policy files loaded
    if bridge_role() == "manager":
        return PrivacyPolicy(mode="blocklist", blocklist=(), allowlist=())

    ctx = gate_context()
    if ctx.enabled:
        return load_gate_policy(ctx)

    mode_override = os.environ.get("COWORK_IMESSAGE_READ_POLICY", "runtime")
    if mode_override in ("allowlist", "blocklist"):
        mode = mode_override
    else:
        # Item 1: apply the same ownership/mode check to read_policy.txt
        can_read_policy = True
        if WRAPPER_MODE == "product":
            try:
                metadata = READ_POLICY_PATH.lstat()
                if not stat.S_ISREG(metadata.st_mode):
                    log(f"read_policy.txt rejected: must be a regular file")
                    can_read_policy = False
                # Root-owned satisfies (same as _load_list)
                elif metadata.st_uid == 0:
                    if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                        log(f"read_policy.txt rejected: has group/world permissions")
                        can_read_policy = False
                elif metadata.st_uid != os.getuid():
                    log(f"read_policy.txt rejected: must be owned by current user (uid {os.getuid()})")
                    can_read_policy = False
                elif metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    log(f"read_policy.txt rejected: must not be group/world-writable")
                    can_read_policy = False
            except FileNotFoundError:
                can_read_policy = False

        if can_read_policy:
            try:
                mode = READ_POLICY_PATH.read_text(encoding="utf-8").strip().lower()
            except FileNotFoundError:
                # Product mode: missing read_policy.txt defaults to allowlist (fail closed)
                if WRAPPER_MODE == "product":
                    mode = "allowlist"
                else:
                    mode = "blocklist"
        else:
            # Product mode: permission check failed, treat as missing → allowlist (fail closed)
            if WRAPPER_MODE == "product":
                mode = "allowlist"
            else:
                mode = "blocklist"

        if mode not in ("allowlist", "blocklist"):
            log(f"invalid read policy {mode!r}; failing closed in allowlist mode")
            mode = "allowlist"

    require_root = os.environ.get("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY") == "1"
    # Product mode: policy files must be uid-owned and not group/world-writable
    require_uid = WRAPPER_MODE == "product"
    return PrivacyPolicy(
        mode=mode,
        blocklist=_load_list(BLOCKLIST_PATH, require_uid_owner=require_uid),
        allowlist=_load_list(ALLOWLIST_PATH, require_root_owner=require_root, require_uid_owner=require_uid),
    )


def load_blocklist() -> list[str]:
    """Backward-compatible loader retained for existing integrations/tests."""
    return list(_load_list(BLOCKLIST_PATH))


def is_send_policy_enabled() -> bool:
    """Check if send_policy.json enables sending. Product mode only; DIY always returns True."""
    if WRAPPER_MODE != "product":
        return True
    try:
        metadata = SEND_POLICY_PATH.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            log(f"send_policy.json rejected: must be a regular file")
            return False
        if metadata.st_uid != os.getuid():
            log(f"send_policy.json rejected: must be owned by current user (uid {os.getuid()})")
            return False
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            log(f"send_policy.json rejected: must not be group/world-writable")
            return False
        policy = json.loads(SEND_POLICY_PATH.read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            log(f"send_policy.json malformed: root must be an object")
            return False
        return policy.get("enabled") is True
    except FileNotFoundError:
        return False
    except (json.JSONDecodeError, OSError) as e:
        log(f"send_policy.json rejected: {e}")
        return False


def _coerce_policy(policy: PrivacyPolicy | list[str]) -> PrivacyPolicy:
    if isinstance(policy, PrivacyPolicy):
        return policy
    return PrivacyPolicy(mode="blocklist", blocklist=tuple(policy), allowlist=())


def _matches_list(chat_id: str, sender: str, entries: tuple[str, ...] | list[str]) -> bool:
    if not entries:
        return False
    cid = chat_id or ""
    snd = sender or ""
    cid_l10 = _last10(cid)
    snd_l10 = _last10(snd)
    for entry in entries:
        entry_l10 = _last10(entry)
        lowered = entry.lower()
        # Group chat IDs (starting with "chat") must match exactly, never via last-10.
        # This prevents "chat1234567890" from colliding with phone "+11234567890".
        entry_is_group = lowered.startswith("chat")
        cid_is_group = cid.lower().startswith("chat")
        snd_is_group = snd.lower().startswith("chat")
        
        # Email: exact case-insensitive match
        if "@" in entry and (lowered == cid.lower() or lowered == snd.lower()):
            return True
        
        # Group chat ID entry: exact case-insensitive match only
        if entry_is_group:
            if lowered == cid.lower() or lowered == snd.lower():
                return True
        # Phone number entry: match last 10 digits, but check each side independently
        elif entry_l10:
            # Match against chat_id only if chat_id is not a group
            if cid_l10 and not cid_is_group and entry_l10 == cid_l10:
                return True
            # Match against sender only if sender is not a group
            if snd_l10 and not snd_is_group and entry_l10 == snd_l10:
                return True
        # Fallback: non-email, non-group entries lacking 10 digits match exactly
        elif "@" not in entry:
            if lowered == cid.lower() or lowered == snd.lower():
                return True
    return False


def _last10(s: str) -> str:
    d = re.sub(r"[^0-9]", "", s or "")
    return d[-10:] if len(d) >= 10 else ""


def is_blocked(chat_id: str, sender: str, policy: PrivacyPolicy | list[str]) -> bool:
    return _matches_list(chat_id, sender, _coerce_policy(policy).blocklist)


def is_read_allowed(chat_id: str, sender: str, policy: PrivacyPolicy | list[str]) -> bool:
    resolved = _coerce_policy(policy)
    if is_blocked(chat_id, sender, resolved):
        return False
    if resolved.source == "gate":
        return _grant_match(chat_id, resolved.allowlist) or _unknown_match(chat_id, resolved)
    if resolved.mode == "allowlist":
        return bool(_matches_list(chat_id, sender, resolved.allowlist))
    return True


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------
_CODE_NEAR_WORD = re.compile(
    r"(?:\b(?:code|verification|OTP|passcode|one[- ]time)\b[^0-9]{0,20}\b(\d{4,8})\b)"
    r"|(?:\b(\d{4,8})\b[^0-9]{0,20}\b(?:code|verification|OTP|passcode)\b)",
    re.IGNORECASE,
)
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def redact(text: str) -> str:
    if not text:
        return text
    text = _CODE_NEAR_WORD.sub("[REDACTED-2FA]", text)
    text = _CARD_RE.sub(lambda m: "[REDACTED-CARD]" if len(re.sub(r"\D", "", m.group(0))) >= 13 else m.group(0), text)
    text = _SSN_RE.sub("[REDACTED-SSN]", text)
    return text


# ---------------------------------------------------------------------------
# Automated / low-signal filters (for the review action)
# ---------------------------------------------------------------------------
_AUTO_PATTERNS = re.compile(
    "|".join(
        [
            r"lyft:.*(requested|on their way|arrived|cancelled)",
            r"uber:.*(on|arriving|trip)",
            r"your .*verification code",
            r"your .*code is",
            r"verification code|one-time password|\botp\b",
            r"actblue|midterms|reelection|\bdonate\b|rush \$\d+",
            r"stop to quit|reply stop",
            r"error invalid number",
            r"delivered|out for delivery|package|shipment",
            r"check-in",
            r"bill is ready|statement is available",
            r"your appointment|appointment reminder",
        ]
    ),
    re.IGNORECASE,
)
_SHORT_CODE = re.compile(r"^[+]?[0-9]{3,6}$")
_REACTION_PREFIX = re.compile(
    r"^(liked|loved|laughed at|emphasized|questioned|disliked|reacted|removed a)"
    r"( a| an)? [“\"'\ufffc]",
    re.IGNORECASE,
)
_ONE_WORD_ACK = {
    "thx", "thanks", "ty", "ok", "okay", "k", "sure", "sounds good",
    "sounds good!", "for sure", "cool", "nice", "great", "got it",
    "yep", "yup", "nope",
}


def is_automated(chat_id: str, text: str) -> bool:
    if _SHORT_CODE.match(chat_id or ""):
        return True
    if "rbm.goog" in (chat_id or ""):
        return True
    if not text:
        return False
    return bool(_AUTO_PATTERNS.search(text))


def is_low_signal(text: str) -> bool:
    if not text:
        return True
    t = text.strip()
    if _REACTION_PREFIX.match(t):
        return True
    if t.lower().rstrip("!. ") in _ONE_WORD_ACK:
        return True
    return False


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _as_number(v: Any, name: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) and not (isinstance(v, str) and v.strip()):
        raise ValueError(f"{name} must be a number")
    try:
        return float(v)
    except Exception:
        raise ValueError(f"{name} must be a number")


def validate_days(v: Any) -> float:
    n = _as_number(v, "days")
    if n <= 0 or n > MAX_DAYS:
        raise ValueError(f"days must be in (0, {MAX_DAYS}]")
    return n


def validate_hours(v: Any) -> float:
    n = _as_number(v, "hours")
    if n <= 0 or n > MAX_HOURS:
        raise ValueError(f"hours must be in (0, {MAX_HOURS}]")
    return n


def validate_limit(v: Any) -> int:
    n = int(_as_number(v, "limit"))
    if n <= 0 or n > MAX_LIMIT:
        raise ValueError(f"limit must be in (0, {MAX_LIMIT}]")
    return n


def validate_search(v: Any) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError("search term required")
    if len(v) > MAX_SEARCH_LEN:
        raise ValueError("search term too long")
    return v


def validate_list_chats_days(v: Any) -> float:
    n = _as_number(v, "days")
    if n <= 0 or n > MAX_LIST_CHATS_DAYS:
        raise ValueError(f"days must be in (0, {MAX_LIST_CHATS_DAYS}]")
    return n


def validate_list_chats_limit(v: Any) -> int:
    """`limit` is an integer in the protocol; reject fractional values."""
    if isinstance(v, bool):
        raise ValueError("limit must be an integer")
    if isinstance(v, float):
        if not v.is_integer():
            raise ValueError("limit must be an integer")
        v = int(v)
    if isinstance(v, str):
        try:
            v = int(v.strip())
        except ValueError:
            raise ValueError("limit must be an integer")
    return validate_limit(v)


def validate_list_chats_query(v: Any) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError("query must be a string")
    if len(v) > MAX_LIST_CHATS_QUERY_LEN:
        raise ValueError("query too long")
    q = v.strip()
    return q or None


def validate_bool(v: Any, name: str, default: bool) -> bool:
    if v is None:
        return default
    if not isinstance(v, bool):
        raise ValueError(f"{name} must be a boolean")
    return v


_EMAIL_ATOM = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
_EMAIL_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_EMAIL_RE = re.compile(
    rf"^{_EMAIL_ATOM}(?:\.{_EMAIL_ATOM})*@"
    rf"{_EMAIL_LABEL}(?:\.{_EMAIL_LABEL})+$"
)
_PHONE_RE = re.compile(r"^[+0-9().\- ]+$")


def validate_chat(v: Any) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError("chat identifier required")
    if len(v) > 200:
        raise ValueError("chat identifier too long")
    return v.strip()


def _agent_recipient_view(
    to: str, contacts: dict[str, str]
) -> dict[str, str]:
    """Agent-safe recipient fields (no raw phone/email)."""
    normalized = _normalize_handle(to)
    if not normalized:
        raise ValueError("unable to derive contact_ref for recipient")
    view = _contact_refs.lookup_match(
        normalized,
        _resolve_contact_name(to, contacts) or unknown_sender_name(normalized),
        contact_handle_label(normalized) or ("email" if "@" in normalized else "phone"),
    )
    view["known"] = normalized in contacts
    return view


def _one_to_one_identifiers(conn: sqlite3.Connection) -> list[str]:
    """Every 1:1 chat identifier and message handle in chat.db (no groups)."""
    rows = conn.execute(
        "SELECT chat_identifier FROM chat WHERE chat_identifier NOT LIKE 'chat%' "
        "UNION SELECT id FROM handle"
    ).fetchall()
    return [i for i in (_decode_db_text(r[0]).strip() for r in rows) if i]


def resolve_ref_via_chatdb(ref: str, kind: str) -> str:
    """Map a thread_ref (1:1 only) or an unsaved number's contact_ref back to
    its handle using chat.db, for people who aren't in Contacts."""
    if not isinstance(ref, str) or not re.fullmatch(r"[0-9a-f]{64}", ref.strip()):
        raise ValueError(f"{kind} must be a 64-character hex string")
    ref = ref.strip()
    key = _contact_refs._hmac_key()
    try:
        conn = open_chatdb_direct()
    except (RuntimeError, sqlite3.Error) as exc:
        log(f"ref resolution: chat.db unavailable: {exc}")
        raise ValueError(f"unknown {kind}") from None
    try:
        for ident in _one_to_one_identifiers(conn):
            if kind == "thread_ref":
                candidate = _contact_refs.make_contact_ref("thread:" + ident, key)
            else:
                normalized = _normalize_handle(ident)
                if not normalized:
                    continue
                candidate = _contact_refs.make_contact_ref(normalized, key)
            if hmac.compare_digest(candidate, ref):
                return ident
    finally:
        conn.close()
    raise ValueError(f"unknown {kind} (group threads can't be used here)")


def resolve_send_recipient(params: dict[str, Any], contacts: dict[str, str]) -> str:
    """Resolve a 1:1 target from contact_ref, thread_ref, or raw to."""
    given = [k for k in ("contact_ref", "thread_ref", "to") if params.get(k) is not None]
    if len(given) > 1:
        raise ValueError("provide only one of contact_ref, thread_ref, or to")
    if not given:
        raise ValueError("contact_ref, thread_ref, or to required")
    if given[0] == "contact_ref":
        try:
            normalized = _contact_refs.resolve_contact_ref(params["contact_ref"], contacts)
        except ValueError:
            return validate_send_recipient(resolve_ref_via_chatdb(params["contact_ref"], "contact_ref"))
        return contact_raw_handle(normalized)
    if given[0] == "thread_ref":
        return validate_send_recipient(resolve_ref_via_chatdb(params["thread_ref"], "thread_ref"))
    return validate_send_recipient(params["to"])


def validate_send_recipient(v: Any) -> str:
    """Validate a send target. Accepts only phone numbers and email addresses.
    Rejects all group chat IDs (any 'chat' prefix).
    """
    identifier = validate_chat(v)

    if identifier.casefold().startswith("chat"):
        raise ValueError("group chat IDs are not supported for sending; use a phone number or email")

    if "@" in identifier:
        if not _EMAIL_RE.fullmatch(identifier):
            raise ValueError("send recipient must be a valid email address or phone number")
        return identifier.strip().lower()

    digits = re.sub(r"\D", "", identifier)
    if len(digits) >= 10 and _PHONE_RE.fullmatch(identifier):
        return identifier.strip()

    raise ValueError("send recipient must be a valid phone number or email address")


def validate_send_text(v: Any) -> str:
    """Bounds-check a message body for outbound send.

    Allows printable Unicode (including emoji) plus \\n, \\r, \\t. Rejects
    other C0 control characters to avoid exotic payloads being relayed
    through Messages.app.
    """
    if not isinstance(v, str):
        raise ValueError("text must be a string")
    if not v:
        raise ValueError("text cannot be empty")
    if len(v) > MAX_SEND_LEN:
        raise ValueError(f"text too long ({len(v)} chars; max {MAX_SEND_LEN})")
    for ch in v:
        if ord(ch) < 0x20 and ch not in ("\n", "\r", "\t"):
            raise ValueError(
                f"text contains disallowed control character U+{ord(ch):04X}"
            )
    # Bidi overrides/isolates and invisible spaces can make the approval page
    # show different text than what is sent. ZWJ (emoji sequences) is allowed.
    hidden = _INVISIBLE_CONTROLS_RE.search(v)
    if hidden:
        raise ValueError(
            f"text contains invisible or bidi control character U+{ord(hidden.group(0)):04X}"
        )
    return v


def validate_service(v: Any) -> str:
    """Normalize the send service. Defaults to iMessage when omitted."""
    if v is None:
        return "iMessage"
    if v not in _SERVICE_ENUM:
        raise ValueError(
            f"service must be one of {_SERVICE_ENUM}, got {v!r}"
        )
    return v


# ---------------------------------------------------------------------------
# AppleScript shellout (send path only)
# ---------------------------------------------------------------------------
def _escape_as_string(s: str) -> str:
    """Escape a Python string for embedding as an AppleScript string literal.

    AppleScript string literals are double-quoted; only `"` and `\\` need
    to be escaped (in that order: backslash first to avoid double-escaping).
    This is used for recipient identifiers and message bodies that have
    already passed validation (printable Unicode + safe whitespace only).
    """
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _run_osascript(script: str, timeout: float = OSASCRIPT_TIMEOUT_S
                   ) -> tuple[int, str, str]:
    """Run `script` via osascript (fed on stdin). Returns (rc, stdout, stderr).

    Separated out from the action functions so tests can monkeypatch it.
    """
    r = subprocess.run(
        ["/usr/bin/osascript", "-"],
        input=script,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()


def _run_send_confirmation(
    *, to: str, resolved_name: str, service: str, text: str
) -> bool:
    """Show the full outbound payload in the native confirmation helper.

    Return True only for the helper's explicit Send exit status. Cancel and
    timeout return False; malformed input or helper failures raise.
    """
    payload = json.dumps(
        {
            "client_name": HOST_DISPLAY_NAME,
            "to": to,
            "resolved_name": resolved_name,
            "service": service,
            "text": text,
        },
        ensure_ascii=False,
    )
    try:
        result = subprocess.run(
            [str(CONFIRM_HELPER_PATH)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=70,
        )
    except subprocess.TimeoutExpired:
        return False
    except OSError as e:
        raise RuntimeError(f"confirmation helper could not start: {e}") from e

    if result.returncode == 0:
        return True
    if result.returncode in (1, 3):
        return False
    detail = (result.stderr or result.stdout or "no output").strip()
    raise RuntimeError(
        f"confirmation helper failed (rc={result.returncode}): {detail}"
    )


# ---------------------------------------------------------------------------
# DB handling
# ---------------------------------------------------------------------------
def _get_snapshot_max_bytes() -> int:
    """Return the configured snapshot size limit in bytes.
    
    Reads IMESSAGE_SNAPSHOT_MAX_MB (integer megabytes) or falls back to
    DEFAULT_SNAPSHOT_MAX_MB. Invalid values fail closed at the default.
    """
    env_value = os.environ.get("IMESSAGE_SNAPSHOT_MAX_MB", "").strip()
    if not env_value:
        return DEFAULT_SNAPSHOT_MAX_MB * 1024 * 1024
    try:
        mb = int(env_value)
        if mb <= 0:
            log(f"IMESSAGE_SNAPSHOT_MAX_MB={mb} invalid; using default {DEFAULT_SNAPSHOT_MAX_MB} MB")
            return DEFAULT_SNAPSHOT_MAX_MB * 1024 * 1024
        return mb * 1024 * 1024
    except ValueError:
        log(f"IMESSAGE_SNAPSHOT_MAX_MB={env_value!r} invalid; using default {DEFAULT_SNAPSHOT_MAX_MB} MB")
        return DEFAULT_SNAPSHOT_MAX_MB * 1024 * 1024


def copy_chatdb() -> sqlite3.Connection:
    """Copy chat.db to an in-memory snapshot using SQLite's backup API.
    
    Returns an open connection to the in-memory snapshot. The caller is
    responsible for closing the connection. This eliminates same-UID disk
    exposure: the snapshot exists only in this process's memory space.
    
    Raises RuntimeError if chat.db + chat.db-wal exceeds the configured
    size limit (IMESSAGE_SNAPSHOT_MAX_MB, default 1024 MB). Large databases
    can cause OOM during the in-memory snapshot; operators should ensure
    adequate memory before raising the limit. SQLite's backup API includes
    uncommitted WAL data in the snapshot, so both files count against the limit.
    """
    if not CHAT_DB_PATH.exists():
        raise RuntimeError(f"chat.db not found at {CHAT_DB_PATH}")
    
    # Check size before attempting snapshot to fail fast on OOM risk.
    # SQLite backup includes WAL data, so count both chat.db and chat.db-wal.
    try:
        db_size = CHAT_DB_PATH.stat().st_size
        wal_path = CHAT_DB_PATH.parent / f"{CHAT_DB_PATH.name}-wal"
        wal_size = wal_path.stat().st_size if wal_path.exists() else 0
        total_size = db_size + wal_size
    except OSError as e:
        raise RuntimeError(f"cannot stat chat.db or WAL: {e}") from e
    
    max_bytes = _get_snapshot_max_bytes()
    if total_size > max_bytes:
        max_mb = max_bytes // (1024 * 1024)
        actual_mb = total_size // (1024 * 1024)
        db_mb = db_size // (1024 * 1024)
        wal_mb = wal_size // (1024 * 1024)
        raise RuntimeError(
            f"chat.db + WAL size ({actual_mb} MB: {db_mb} MB db + {wal_mb} MB wal) "
            f"exceeds snapshot limit ({max_mb} MB); "
            f"set IMESSAGE_SNAPSHOT_MAX_MB to a higher value or archive old messages"
        )
    
    source = None
    destination = None
    try:
        # chat.db is live and may contain uncheckpointed WAL rows. Do not use
        # immutable=1 here: it asserts the file cannot change and disables
        # locking/change detection. The online backup API supplies the snapshot.
        source_uri = f"{CHAT_DB_PATH.resolve().as_uri()}?mode=ro&cache=private"
        source = sqlite3.connect(source_uri, uri=True, timeout=5)
        # Use in-memory database instead of disk-based tempfile
        destination = sqlite3.connect(":memory:")
        destination.text_factory = bytes
        source.backup(destination)
        return destination
    except Exception:
        if destination is not None:
            destination.close()
        raise
    finally:
        if source is not None:
            source.close()


def to_apple_ns(unix_seconds: float) -> int:
    return int((unix_seconds - APPLE_EPOCH) * 1_000_000_000)


def from_apple_ns(ns: int) -> datetime:
    return datetime.fromtimestamp(ns / 1_000_000_000 + APPLE_EPOCH)


def fetch_messages(
    conn: sqlite3.Connection,
    cutoff_ns: int,
    *,
    search: str | None = None,
    chat_filter_substr: str | None = None,
) -> list[dict]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT c.chat_identifier,
               COALESCE(c.display_name, ''),
               m.date,
               m.is_from_me,
               COALESCE(h.id, ''),
               m.text,
               m.attributedBody
        FROM message m
        JOIN chat_message_join cmj ON cmj.message_id = m.ROWID
        JOIN chat c ON c.ROWID = cmj.chat_id
        LEFT JOIN handle h ON h.ROWID = m.handle_id
        WHERE m.date > ?
        ORDER BY c.chat_identifier, m.date ASC
        """,
        (cutoff_ns,),
    )
    out: list[dict] = []
    for row in cur.fetchall():
        chat_id = (row[0] or b"").decode("utf-8", "ignore")
        disp = (row[1] or b"").decode("utf-8", "ignore")
        ts_ns = row[2]
        is_me = bool(row[3])
        sender = (row[4] or b"").decode("utf-8", "ignore")
        raw_text = row[5]
        attrib = row[6]
        text = raw_text.decode("utf-8", "ignore") if raw_text else ""
        if not text and attrib:
            text = decode_attributed_body(attrib)

        if chat_filter_substr and chat_filter_substr.lower() not in chat_id.lower() \
                and chat_filter_substr.lower() not in sender.lower():
            continue
        if search and search.lower() not in text.lower():
            continue

        out.append(
            {
                "chat_id": chat_id,
                "display_name": disp,
                "ts_ns": ts_ns,
                "ts": from_apple_ns(ts_ns).isoformat(timespec="seconds"),
                "is_from_me": is_me,
                "sender": sender,
                "text": text,
            }
        )
    return out


def apply_read_policy(
    msgs: list[dict], policy: PrivacyPolicy | list[str]
) -> list[dict]:
    return [m for m in msgs if is_read_allowed(m["chat_id"], m["sender"], policy)]


def apply_blocklist(msgs: list[dict], blocklist: list[str]) -> list[dict]:
    """Backward-compatible alias for blocklist-only callers."""
    return apply_read_policy(msgs, blocklist)


def filter_contacts(
    contacts: dict[str, str], policy: PrivacyPolicy | list[str]
) -> dict[str, str]:
    return {
        handle: name
        for handle, name in contacts.items()
        if is_read_allowed(handle, handle, policy)
    }


# ---------------------------------------------------------------------------
# Chat resolution: "Alex Example" | phone | email -> chat_identifier substring
# ---------------------------------------------------------------------------
def resolve_chat_filter(q: str, contacts: dict[str, str]) -> str:
    """Return a substring suitable for matching chat_identifier/sender."""
    digits = re.sub(r"[^0-9]", "", q)
    if len(digits) >= 10:
        return digits[-10:]
    if "@" in q:
        return q
    # Treat as a contact-name query.
    ql = q.lower().strip()
    for d10, name in contacts.items():
        if ql in name.lower():
            return d10
    # No match — fall through to raw substring match, which usually fails.
    return q


# ---------------------------------------------------------------------------
# Classification (review action)
# ---------------------------------------------------------------------------
def classify_chats(
    msgs: list[dict],
    contacts: dict[str, str],
    participants: dict[str, list[str]] | None = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    participants = participants or {}
    chats: dict[str, list[dict]] = defaultdict(list)
    for m in msgs:
        chats[m["chat_id"]].append(m)

    needs_reply: list[dict] = []
    low_priority: list[dict] = []
    skip: list[dict] = []

    for chat_id, ms in chats.items():
        ms.sort(key=lambda x: x["ts_ns"])
        last = ms[-1]
        if last["is_from_me"]:
            continue  # already replied

        last_text = last["text"] or ""
        display = last.get("display_name") or ""
        # Distinguish 1:1 vs group. For 1:1 the chat_identifier is the
        # handle itself (phone or email); for groups it's "chatNNNNN".
        is_group = chat_id.startswith("chat") and not re.fullmatch(r"[+0-9@.]+", chat_id)
        if is_group:
            # Always label groups by group name / participants, never by
            # the last sender — otherwise a 5-person thread looks like a
            # 1:1 with whoever just happened to speak last.
            contact_name = ""
            if not display:
                display = group_label(participants.get(chat_id, []), contacts)
        else:
            contact_name = lookup_name(chat_id, last["sender"], contacts)

        automated_last = is_automated(chat_id, last_text)
        has_human = any(
            not m["is_from_me"] and not is_automated(chat_id, m.get("text", ""))
            for m in ms
        )

        view = thread_view(
            chat_id,
            last["sender"],
            contacts,
            display_name=display,
            participants=participants.get(chat_id, []),
        )
        if not view["is_group"] and not view["name"]:
            view["name"] = contact_name or display
        entry = {
            **view,
            "last_ts": last["ts"],
            "last_text": redact(last_text)[:MAX_TEXT_SNIPPET],
            "context": [
                {
                    "ts": m["ts"],
                    "me": m["is_from_me"],
                    "text": redact(m.get("text", "") or "")[:400],
                }
                for m in ms[-MAX_CONTEXT_MESSAGES:]
            ],
            "msg_count": len(ms),
        }

        if automated_last and not has_human:
            skip.append(entry)
        elif is_low_signal(last_text):
            low_priority.append(entry)
        else:
            needs_reply.append(entry)

    for bucket in (needs_reply, low_priority, skip):
        bucket.sort(key=lambda x: x["last_ts"], reverse=True)
    return needs_reply, low_priority, skip


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
def action_review(params, conn, contacts, privacy_policy):
    days = validate_days(params.get("days", 2))
    cutoff_ns = to_apple_ns(time.time() - days * 86400)
    msgs = fetch_messages(conn, cutoff_ns)
    watch_policy = scoped_policy(privacy_policy, "watch")
    msgs = apply_scope(msgs, watch_policy, "watch")
    participants = load_chat_participants(conn)
    needs_reply, low_priority, skip = classify_chats(msgs, contacts, participants)
    return {
        "days": days,
        "counts": {
            "needs_reply": len(needs_reply),
            "low_priority": len(low_priority),
            "skip": len(skip),
            "total_messages": len(msgs),
        },
        "needs_reply": needs_reply,
        "low_priority": low_priority,
        # Skip bucket summary only — don't ship 2FA codes and Uber updates
        # into the agent context.
        "skip_summary": [
            {
                "name": e["name"],
                "label": e["label"],
                "is_group": e["is_group"],
                "last_ts": e["last_ts"],
            }
            for e in skip[:20]
        ],
    }


def action_search(params, conn, contacts, privacy_policy):
    term = validate_search(params.get("term"))
    days = validate_days(params.get("days", 30))
    limit = validate_limit(params.get("limit", 100))
    cutoff_ns = to_apple_ns(time.time() - days * 86400)
    msgs = fetch_messages(conn, cutoff_ns, search=term)
    msgs = apply_scope(msgs, privacy_policy, "read")
    # Sort descending by timestamp so newest matches come first.
    msgs.sort(key=lambda x: x["ts_ns"], reverse=True)
    msgs = msgs[:limit]
    participants = _participants_if_groups(conn, msgs)
    matches = [message_view(m, contacts, participants) for m in msgs]
    return {"term": term, "days": days, "match_count": len(matches), "matches": matches}


def _participants_if_groups(conn, msgs: list[dict]) -> dict[Any, list[str]]:
    if conn is None or not any(_chat_kind(m["chat_id"], None) == "group" for m in msgs):
        return {}
    return load_chat_participants(conn)


@dataclass
class ReadTarget:
    """Which thread a per-contact read targets. Exactly one of substr or ref is set."""

    query: str | None
    substr: str | None
    thread_ref: str | None
    resolved: dict[str, Any]


def resolve_read_target(params: dict[str, Any], contacts: dict[str, str]) -> ReadTarget:
    """`contact_ref` (a person), `thread_ref` (a group), or legacy `chat`
    (name / phone / email / group id). Only one may be given."""
    given = [k for k in ("contact_ref", "thread_ref", "chat") if params.get(k) is not None]
    if len(given) != 1:
        raise ValueError("provide exactly one of contact_ref, thread_ref, or chat")
    if given[0] == "contact_ref":
        try:
            key = _contact_refs.resolve_contact_ref(params["contact_ref"], contacts)
        except ValueError:
            key = _normalize_handle(resolve_ref_via_chatdb(params["contact_ref"], "contact_ref"))
        return ReadTarget(None, key, None, person_view(key, contacts))
    if given[0] == "thread_ref":
        ref = params["thread_ref"]
        if not isinstance(ref, str) or not re.fullmatch(r"[0-9a-f]{64}", ref.strip()):
            raise ValueError("thread_ref must be a 64-character hex string")
        return ReadTarget(None, None, ref.strip(), {"is_group": True, "thread_ref": ref.strip()})
    chat_q = validate_chat(params.get("chat"))
    substr = resolve_chat_filter(chat_q, contacts)
    resolved = person_view(substr, contacts) if substr in contacts else {"name": ""}
    return ReadTarget(chat_q, substr, None, resolved)


def fetch_target_messages(conn, cutoff_ns: int, target: ReadTarget) -> list[dict]:
    if target.thread_ref is None:
        return fetch_messages(conn, cutoff_ns, chat_filter_substr=target.substr)
    refs: dict[str, bool] = {}
    out = []
    for m in fetch_messages(conn, cutoff_ns):
        cid = m["chat_id"]
        if cid not in refs:
            refs[cid] = hmac.compare_digest(thread_ref(cid), target.thread_ref)
        if refs[cid]:
            out.append(m)
    return out


def _target_fields(target: ReadTarget) -> dict[str, Any]:
    fields: dict[str, Any] = {"resolved": target.resolved}
    if target.query is not None:
        fields["chat_query"] = target.query
    return fields


def action_chat_history(params, conn, contacts, privacy_policy):
    days = validate_days(params.get("days", 14))
    limit = validate_limit(params.get("limit", 100))
    visible_contacts = filter_contacts(contacts, privacy_policy)
    target = resolve_read_target(
        params, contacts if params.get("contact_ref") is not None else visible_contacts
    )
    cutoff_ns = to_apple_ns(time.time() - days * 86400)
    msgs = fetch_target_messages(conn, cutoff_ns, target)
    msgs = apply_scope(msgs, privacy_policy, "read")
    msgs.sort(key=lambda x: x["ts_ns"])
    msgs = msgs[-limit:]
    participants = _participants_if_groups(conn, msgs)
    out = [message_view(m, visible_contacts, participants) for m in msgs]
    if target.thread_ref and msgs:
        target.resolved = {
            key: out[-1][key] for key in ("is_group", "name", "label", "thread_ref")
        }
    return {**_target_fields(target), "count": len(out), "messages": out}


def action_response_stats(params, conn, contacts, privacy_policy):
    hours = validate_hours(params.get("hours", 24))
    visible_contacts = filter_contacts(contacts, privacy_policy)
    target = resolve_read_target(
        params, contacts if params.get("contact_ref") is not None else visible_contacts
    )
    cutoff_ns = to_apple_ns(time.time() - hours * 3600)
    msgs = fetch_target_messages(conn, cutoff_ns, target)
    msgs = apply_scope(msgs, privacy_policy, "read")
    msgs.sort(key=lambda x: x["ts_ns"])

    deltas: list[float] = []
    pending_them: dict | None = None
    for m in msgs:
        if not m["is_from_me"]:
            # First inbound in a run; later inbounds don't reset the clock.
            if pending_them is None:
                pending_them = m
        else:
            if pending_them is not None:
                dt = (m["ts_ns"] - pending_them["ts_ns"]) / 1_000_000_000
                if dt >= 0:
                    deltas.append(dt)
                pending_them = None

    def fmt(sec: float | None) -> str | None:
        if sec is None:
            return None
        if sec < 60:
            return f"{sec:.0f}s"
        if sec < 3600:
            return f"{sec / 60:.1f}m"
        if sec < 86400:
            return f"{sec / 3600:.2f}h"
        return f"{sec / 86400:.2f}d"

    avg = sum(deltas) / len(deltas) if deltas else None
    return {
        **_target_fields(target),
        "hours": hours,
        "sample_size": len(deltas),
        "avg_seconds": avg,
        "avg_human": fmt(avg),
        "median_seconds": sorted(deltas)[len(deltas) // 2] if deltas else None,
        "min_seconds": min(deltas) if deltas else None,
        "max_seconds": max(deltas) if deltas else None,
        "total_inbound_messages": sum(1 for m in msgs if not m["is_from_me"]),
        "total_outbound_messages": sum(1 for m in msgs if m["is_from_me"]),
    }


def action_contacts_lookup(params, conn, contacts, privacy_policy):
    name = params.get("name", "")
    if not isinstance(name, str) or not name.strip() or len(name) > 100:
        raise ValueError("name must be a 1..100 char string")
    nl = name.lower()
    policy = _coerce_policy(privacy_policy)
    gate_mode = policy.source == "gate"
    matches = []
    for handle, full_name in contacts.items():
        # Allowlist gates message reads, not contact discovery. Users need
        # contacts_lookup to resolve names before send/chat_history; an empty
        # hardened allowlist must not hide every contact. Blocklist still applies.
        if bridge_role() != "manager" and is_blocked(handle, handle, privacy_policy):
            continue
        if nl in full_name.lower():
            label = contact_handle_label(handle) or (
                "email" if "@" in handle else "phone"
            )
            match = _contact_refs.lookup_match(handle, full_name, label)
            if gate_mode:
                match["scopes"] = grant_scopes_for(handle, policy)
            matches.append(match)
    result = {"query": name, "match_count": len(matches), "matches": matches[:25]}
    if gate_mode and policy.gate_error:
        result["gate_error"] = policy.gate_error
    return result


action_contacts_lookup.needs_db = False  # type: ignore[attr-defined]


# chat.style in chat.db is IMChatStyle: 43 (ASCII '+') = group chat,
# 45 (ASCII '-') = one-to-one "instant message" chat. Same mapping as
# ENGINEERING_PLAN §2.4 and the review classifier's chat-id heuristic.
_CHAT_STYLE_GROUP = 43
_CHAT_STYLE_DIRECT = 45


def _chat_kind(chat_id: str, style: Any) -> str:
    if style == _CHAT_STYLE_GROUP:
        return "group"
    if style == _CHAT_STYLE_DIRECT:
        return "direct"
    # Fallback heuristic, same rule classify_chats uses.
    is_group = chat_id.startswith("chat") and not re.fullmatch(r"[+0-9@.]+", chat_id)
    return "group" if is_group else "direct"


def _decode_db_text(v: Any) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", "ignore")
    return v or ""


def action_list_chats(params, conn, contacts, privacy_policy):
    """Enumerate threads with recent activity, without any message content.

    Management-bridge only (see ROLE_ACTIONS). Intended for policy discovery:
    the app shows this list so the user can build an allowlist/blocklist. The
    query deliberately never selects `message.text` or `message.attributedBody`
    and the read policy is not applied — the point is to see which threads
    exist so a policy can be written about them.
    """
    days = validate_list_chats_days(params.get("days", LIST_CHATS_DEFAULT_DAYS))
    limit = validate_list_chats_limit(params.get("limit", LIST_CHATS_DEFAULT_LIMIT))
    include_groups = validate_bool(params.get("include_groups"), "include_groups", True)
    query = validate_list_chats_query(params.get("query"))
    cutoff_ns = to_apple_ns(time.time() - days * 86400)

    cur = conn.cursor()
    sql = """
        SELECT c.ROWID,
               c.chat_identifier,
               COALESCE(c.display_name, ''),
               COALESCE(c.service_name, ''),
               c.style,
               COUNT(m.ROWID),
               MAX(m.date)
        FROM chat c
        JOIN chat_message_join cmj ON cmj.chat_id = c.ROWID
        JOIN message m ON m.ROWID = cmj.message_id
        WHERE m.date > ?
        GROUP BY c.ROWID
        ORDER BY MAX(m.date) DESC
        """
    post_filtering = query is not None or not include_groups
    candidate_limit = limit if not post_filtering else max(limit + 1, LIST_CHATS_FILTER_SCAN_LIMIT)
    if not post_filtering:
        # No post-filtering: let SQLite stop after limit+1 rows so we can
        # report truncation without pulling every chat.
        cur.execute(sql + " LIMIT ?", (cutoff_ns, limit + 1))
    else:
        # Query/group filters happen after participant labels are assembled.
        # Bound the candidate scan anyway so filtered requests cannot walk a
        # whole large chat database before returning no matches.
        cur.execute(sql + " LIMIT ?", (cutoff_ns, candidate_limit + 1))
    rows = cur.fetchall()
    candidate_truncated = len(rows) > candidate_limit
    rows = rows[:candidate_limit]

    # Participants only for the candidate chats (bounded by LIMIT above), not
    # a full chat_handle_join scan.
    participants_by_chat = load_chat_participants(conn, (row[0] for row in rows))
    ql = query.lower() if query else None
    items: list[dict] = []
    for row in rows:
        chat_rowid = int(row[0])
        chat_id = _decode_db_text(row[1])
        display = _decode_db_text(row[2])
        service = _decode_db_text(row[3])
        style = row[4]
        message_count = int(row[5] or 0)
        last_ns = row[6]
        if not chat_id:
            continue
        kind = _chat_kind(chat_id, style)
        if kind == "group" and not include_groups:
            continue
        participants = list(participants_by_chat.get(chat_rowid, []))
        if kind == "direct" and not participants:
            participants = [chat_id]
        if kind == "group":
            label = display or group_label(participants, contacts, reveal_unknown=True) or chat_id
        else:
            label = lookup_name(chat_id, chat_id, contacts) or display or chat_id
        if ql is not None:
            haystack = [label.lower(), display.lower(), chat_id.lower()]
            haystack.extend(p.lower() for p in participants)
            if not any(ql in h for h in haystack):
                continue
        items.append(
            {
                "chat_id": chat_id,
                "kind": kind,
                "display_name": display,
                "label": label,
                "participants": participants[:MAX_LIST_CHATS_PARTICIPANTS],
                "participant_count": len(participants),
                "service": service,
                "message_count": message_count,
                "last_activity_date": (
                    from_apple_ns(last_ns).date().isoformat() if last_ns is not None else None
                ),
            }
        )
        if len(items) > limit:
            break

    truncated = len(items) > limit or candidate_truncated
    items = items[:limit]
    return {
        "window_days": days,
        "chat_count": len(items),
        "truncated": truncated,
        "chats": items,
    }


def _gate_status(policy: PrivacyPolicy) -> dict[str, Any]:
    ctx = gate_context()
    if not ctx.enabled:
        return {"configured": False}
    return {
        "configured": True,
        "host": ctx.client.config.host if ctx.client is not None else None,
        "reachable": policy.source == "gate" and policy.gate_error is None,
        "error": policy.gate_error,
        "grant_counts": {scope: len(getattr(policy, scope)) for scope in GRANT_SCOPES},
        "unknown_senders": policy.unknown_enabled,
    }


def action_status(params, conn, contacts, privacy_policy):
    """Return compatibility and local-install status without reading messages."""
    policy = _coerce_policy(privacy_policy)
    return {
        "helper_version": HELPER_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "bridge_role": bridge_role(),
        "allowed_actions": sorted(allowed_actions()),
        "product_id": PRODUCT_ID,
        "wrapper_mode": WRAPPER_MODE,
        "host_display_name": HOST_DISPLAY_NAME,
        "launchd_label": "com.jeffhuber.grokbot-imessage" if WRAPPER_MODE == "baked" else None,
        "confirmation_helper_path": str(CONFIRM_HELPER_PATH),
        "code_root": str(CODE_ROOT),
        "bridge_root": str(BRIDGE_ROOT),
        "policy_dir": str(POLICY_ROOT),
        "install_root": str(CODE_ROOT),
        "python_version": sys.version.split()[0],
        "read_policy": {
            "mode": policy.mode,
            "source": policy.source,
            "allowlist_entries": len(policy.allowlist),
            "blocklist_entries": len(policy.blocklist),
            "root_owned_required": os.environ.get("COWORK_IMESSAGE_REQUIRE_ROOT_POLICY") == "1",
        },
        "gate": _gate_status(policy),
        "checks": {
            "chat_db_exists": CHAT_DB_PATH.is_file(),
            "chat_db_readable": os.access(CHAT_DB_PATH, os.R_OK),
            "confirmation_helper_exists": CONFIRM_HELPER_PATH.is_file(),
            "confirmation_helper_executable": os.access(CONFIRM_HELPER_PATH, os.X_OK),
            "requests_dir_exists": REQUESTS_DIR.is_dir(),
            "responses_dir_exists": RESPONSES_DIR.is_dir(),
        },
    }


action_status.needs_db = False  # type: ignore[attr-defined]
action_status.needs_contacts = False  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Send actions (AppleScript-driven)
# ---------------------------------------------------------------------------
def _resolve_contact_name(to: str, contacts: dict[str, str]) -> str:
    """Best-effort name lookup from phone or email targets.

    Group-chat IDs return "" — not because we couldn't look
    them up, but because the Contacts-side loader keys on normalized
    phone numbers and emails only.
    """
    key = _normalize_handle(to)
    return contacts.get(key, "") if key else ""


def _deliver_message(to: str, text: str, service: str) -> None:
    """Send via Messages.app. Callers must have validated all three values.

    The `service type` slot is an AppleScript enum, not a string, so the
    clause is picked statically from the validated service name.
    """
    if service == "iMessage":
        svc_clause = "1st service whose service type = iMessage"
    else:  # SMS — already validated against _SERVICE_ENUM
        svc_clause = "1st service whose service type = SMS"

    # Pass the body directly in the AppleScript with proper escaping.
    # This eliminates the tempfile race where a malicious same-UID process
    # could replace the file between write and read.
    script = (
        f'set msgBody to "{_escape_as_string(text)}"\n'
        f'tell application "Messages"\n'
        f'    set svc to {svc_clause}\n'
        f'    send msgBody to buddy "{_escape_as_string(to)}" of svc\n'
        f'end tell\n'
    )
    rc, stdout, stderr = _run_osascript(script)
    if rc != 0:
        # AppleScript errors quote the buddy handle; keep that out of responses.
        log(f"osascript send failed (rc={rc}): {stderr or stdout or 'no output'}")
        raise RuntimeError(
            f"Messages could not send the message (osascript rc={rc}); "
            "check that the service matches the recipient and see control/log.txt"
        )


def action_send_preview(params, conn, contacts, privacy_policy):
    """Non-destructive: resolve the recipient and return what *would* be sent.

    Intended flow — the agent calls `send_preview` first, shows the preview
    to the user (including any contact-name resolution and a "blocked"
    flag if the target is in the blocklist), gets explicit confirmation,
    then calls `send` with the same params AND echoes back the `send_nonce`
    we mint here. v0.4.0+: the nonce is bound to the exact previewed
    payload and expires after SEND_NONCE_TTL seconds, so a forged `send`
    that skips preview — or swaps the body between preview and send — is
    rejected helper-side.
    """
    if not is_send_policy_enabled():
        raise ValueError("send operations are disabled by policy")
    if _coerce_policy(privacy_policy).source == "gate":
        return _gate_send_preview(params, contacts, privacy_policy)

    to = resolve_send_recipient(params, contacts)
    text = validate_send_text(params.get("text"))
    service = validate_service(params.get("service"))

    send_nonce = mint_send_nonce(to, text, service)

    resolved_name = (
        _resolve_contact_name(to, contacts)
        if is_read_allowed(to, to, privacy_policy)
        else ""
    )
    recipient_view = _agent_recipient_view(to, contacts)
    if resolved_name:
        recipient_view = {**recipient_view, "name": resolved_name}
    return {
        "preview": {
            **recipient_view,
            "resolved_name": resolved_name,
            "service": service,
            "text": text,
            "text_length": len(text),
            "blocked": is_blocked(to, to, privacy_policy),
        },
        "send_nonce": send_nonce,
        "send_nonce_ttl_seconds": SEND_NONCE_TTL,
    }


action_send_preview.needs_db = False  # type: ignore[attr-defined]


def action_send(params, conn, contacts, privacy_policy):
    """Send an iMessage (or SMS via iPhone relay) via AppleScript.

    The message body is escaped and embedded directly in the AppleScript code,
    eliminating the tempfile race where a same-UID process could swap the file
    between write and AppleScript read. validate_send_text rejects control
    characters (except \\n, \\r, \\t), so the text is printable Unicode plus
    safe whitespace. _escape_as_string escapes backslash and double-quote for
    AppleScript string literals.

    Recipient identifiers are also escaped inline as AppleScript string literals
    after passing validate_send_recipient (≤200 chars, stripped).

    The `service type` slot is an AppleScript enum, not a string. We pick
    the clause statically from the validated service name so no untrusted
    input is ever interpolated into that slot.
    """
    if not is_send_policy_enabled():
        raise ValueError("send operations are disabled by policy")
    if _coerce_policy(privacy_policy).source == "gate":
        return _gate_send(params, contacts, privacy_policy)

    to = resolve_send_recipient(params, contacts)
    text = validate_send_text(params.get("text"))
    service = validate_service(params.get("service"))

    if is_blocked(to, to, privacy_policy):
        raise ValueError("refusing to send: recipient is in contacts/blocked_chats.txt")

    # v0.4.0+: helper-side send gate. `send_preview` must have been called
    # first for this exact (to, text, service) triple, and the resulting
    # single-use nonce must be echoed back within the TTL window. This
    # enforces preview-then-confirm even if the bridge has been bypassed
    # by some process writing directly into control/requests/.
    consume_send_nonce(params.get("send_nonce"), to, text, service)

    # Require explicit human approval before AppleScript sends. The native
    # helper shows both the resolved and raw recipient plus the complete body
    # in a scrollable view. Cancel is the keyboard default and all unexpected
    # outcomes fail closed.
    resolved_name = _resolve_contact_name(to, contacts)
    if not _run_send_confirmation(
        to=to,
        resolved_name=resolved_name,
        service=service,
        text=text,
    ):
        raise RuntimeError(
            "send cancelled by user or timed out (60s dialog limit)"
        )

    _deliver_message(to, text, service)

    recipient_view = _agent_recipient_view(to, contacts)
    resolved_name = _resolve_contact_name(to, contacts)
    if resolved_name:
        recipient_view = {**recipient_view, "name": resolved_name}
    return {
        "sent": {
            **recipient_view,
            "resolved_name": resolved_name,
            "service": service,
            "text_length": len(text),
            "sent_at": datetime.now().isoformat(timespec="seconds"),
        }
    }


action_send.needs_db = False  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Approval gate actions (gate mode only)
#
# In gate mode the root-owned gate.json names an approval service. Grants
# (send / read / watch) come from the gate; anything not granted becomes an
# approval the owner decides on their phone. The helper can request and
# revoke, never approve. Gate failures fail closed.
# ---------------------------------------------------------------------------
_E164_RE = re.compile(r"^\+[1-9]\d{6,14}$")
_DURATION_RE = re.compile(r"^(\d+)\s*([mhdw])$")
_DURATION_UNITS = {"m": 60, "h": 3600, "d": 86400, "w": 604800}
MAX_GRANT_DURATION_S = 366 * 86400
UNKNOWN_CONTACT_NAME = "Unknown contact"
MAX_INBOX_LIMIT = 200
INBOX_SCAN_LIMIT = 2000
INBOX_FIRST_RUN_HOURS = 24
WATCH_TICK_SCAN_LIMIT = 10000
_MAX_CURSOR = 2**63 - 1
_STATE_MAX_BYTES = 64 * 1024


def gate_handle(raw: str) -> str:
    """Express a sendable handle the way the gate stores it: E.164 or lowercased email."""
    s = (raw or "").strip()
    if "@" in s:
        return s.lower()
    digits = re.sub(r"\D", "", s)
    if s.startswith("+"):
        candidate = "+" + digits
    elif len(digits) == 10:
        candidate = "+1" + digits
    elif len(digits) == 11 and digits.startswith("1"):
        candidate = "+" + digits
    else:
        raise ValueError("recipient phone number needs a country code")
    if not _E164_RE.match(candidate):
        raise ValueError("recipient is not a valid E.164 phone number")
    return candidate


def parse_grant_duration(value: Any) -> int | None:
    """'always' -> None (permanent); '30m', '1d', '1w', or seconds -> seconds."""
    if value is None:
        raise ValueError("duration required: e.g. '1d', '1w', or 'always'")
    if isinstance(value, str) and value.strip().lower() == "always":
        return None
    if isinstance(value, bool):
        raise ValueError("duration must be a string like '1d' or a number of seconds")
    if isinstance(value, int):
        seconds = value
    elif isinstance(value, str):
        m = _DURATION_RE.match(value.strip().lower())
        if not m:
            raise ValueError("duration must look like '30m', '12h', '1d', '1w', or 'always'")
        seconds = int(m.group(1)) * _DURATION_UNITS[m.group(2)]
    else:
        raise ValueError("duration must be a string like '1d' or a number of seconds")
    if seconds < 60:
        raise ValueError("duration must be at least 1 minute")
    if seconds > MAX_GRANT_DURATION_S:
        raise ValueError("duration is longer than a year; use 'always' instead")
    return seconds


def validate_scopes(v: Any) -> list[str]:
    items = [v] if isinstance(v, str) else v
    if not isinstance(items, list) or not items:
        raise ValueError(f"scopes must be a non-empty list drawn from {GRANT_SCOPES}")
    if any(s not in GRANT_SCOPES for s in items):
        raise ValueError(f"scopes must be drawn from {GRANT_SCOPES}")
    return sorted(set(items))


def _validate_cursor(v: Any, name: str = "cursor") -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > _MAX_CURSOR:
        raise ValueError(f"{name} must be a non-negative integer")
    return v


def _require_gate(privacy_policy) -> tuple[GateContext, PrivacyPolicy]:
    policy = _coerce_policy(privacy_policy)
    ctx = gate_context()
    if policy.source != "gate" or not ctx.enabled:
        raise ValueError("the approval gate is not configured on this install")
    if policy.gate_error or ctx.client is None:
        raise RuntimeError(
            f"approval gate unavailable, refusing: {policy.gate_error or ctx.error}"
        )
    return ctx, policy


def _gate_call(ctx: GateContext, fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ctx.module.GateUnavailable as exc:
        log(f"gate: {fn.__name__} failed: {exc}")
        raise RuntimeError(GATE_UNAVAILABLE_MESSAGE) from None


def _gate_request_error(exc) -> Exception:
    """Fixed agent-facing messages; the gate's detail (which can echo the
    payload, handle included) goes to the log only."""
    log(f"gate: request rejected ({exc.status}): {exc.detail}")
    if exc.status == 429:
        retry = next(
            (v for k, v in exc.headers.items() if k.lower() == "retry-after"), None
        )
        suffix = f"; retry in {int(retry)}s" if retry and str(retry).isdigit() else ""
        return RuntimeError(f"approval request rate limit reached{suffix}")
    if exc.status == 422:
        return ValueError("the approval gate rejected the request as invalid")
    return RuntimeError(f"the approval gate refused the request (HTTP {exc.status})")


def _gate_audit(ctx: GateContext, event: str, **kwargs) -> None:
    """Best effort: the message is already out, so an audit failure is only logged."""
    try:
        ctx.client.audit(event, **kwargs)
    except ctx.errors as exc:
        log(f"gate: audit {event} failed: {exc}")


def _prepare_gate_send(params, contacts, policy: PrivacyPolicy):
    to = resolve_send_recipient(params, contacts)
    text = validate_send_text(params.get("text"))
    service = validate_service(params.get("service"))
    if is_blocked(to, to, policy):
        raise ValueError("refusing to send: recipient is in contacts/blocked_chats.txt")
    handle = gate_handle(to)
    name = expected_display_name(handle, contacts)
    return handle, text, service, name, _agent_recipient_view(handle, contacts)


def _origin_fields(handle: str, contacts: dict[str, str]) -> dict[str, str]:
    return {"contact_origin": contact_origin(handle, contacts)}


def _send_grant_still_active(ctx: GateContext, handle: str, contacts: dict[str, str]) -> bool:
    """Re-read the gate immediately before a grant-path send so a revoke or
    expiry takes effect even for requests already queued in this drain."""
    fresh = load_gate_policy(ctx, contacts)
    return fresh.gate_error is None and handle in fresh.send


def _gate_send_preview(params, contacts, privacy_policy):
    _ctx, policy = _require_gate(privacy_policy)
    handle, text, service, _name, view = _prepare_gate_send(params, contacts, policy)
    granted = handle in policy.send
    return {
        "preview": {
            **view,
            "service": service,
            "text": text,
            "text_length": len(text),
            "blocked": False,
        },
        "authorization": "send_grant" if granted else "approval_required",
    }


def _gate_send(params, contacts, privacy_policy):
    ctx, policy = _require_gate(privacy_policy)
    handle, text, service, name, view = _prepare_gate_send(params, contacts, policy)

    if handle in policy.send and _send_grant_still_active(ctx, handle, contacts):
        _deliver_message(handle, text, service)
        _gate_audit(
            ctx,
            "send",
            handle=handle,
            detail={"via": "send_grant", "service": service, "text_length": len(text)},
        )
        return {
            "status": "sent",
            "sent": {
                **view,
                "via": "send_grant",
                "service": service,
                "text_length": len(text),
                "sent_at": datetime.now().isoformat(timespec="seconds"),
            },
        }

    payload = {
        "handle": handle,
        "display_name": name,
        "service": service,
        "text": text,
        **_origin_fields(handle, contacts),
    }
    try:
        approval = _gate_call(ctx, ctx.client.create_approval, "send", payload)
    except ctx.module.GateError as exc:
        raise _gate_request_error(exc) from None
    return {
        "status": "pending_approval",
        "approval_id": approval["id"],
        "approve_url": approval.get("approve_url"),
        "expires_at": approval.get("expires_at"),
        "recipient": view,
        "service": service,
        "text_length": len(text),
    }


def action_send_commit(params, conn, contacts, privacy_policy):
    """Send the gate-stored payload of an approved send, exactly once.

    The request carries only approval_id. Recipient, service, and text all
    come from the gate, so nothing the caller sends can change what goes out.
    """
    if not is_send_policy_enabled():
        raise ValueError("send operations are disabled by policy")
    ctx, policy = _require_gate(privacy_policy)
    approval_id = ctx.module.validate_approval_id(params.get("approval_id"))
    try:
        consumed = _gate_call(ctx, ctx.client.consume, approval_id)
    except ctx.module.GateError as exc:
        if exc.status == 404:
            raise ValueError("unknown approval_id") from None
        status = exc.detail_status
        if exc.status == 409 and status == "pending":
            return {"status": "pending_approval", "approval_id": approval_id}
        if exc.status == 409 and status:
            raise ValueError(f"approval is {status}; nothing was sent") from None
        raise _gate_request_error(exc) from None

    payload = consumed["payload"]
    handle = validate_send_recipient(payload.get("handle"))
    if gate_handle(handle) != handle:
        raise RuntimeError("gate returned a malformed recipient; nothing was sent")
    text = validate_send_text(payload.get("text"))
    service = validate_service(payload.get("service"))
    if is_blocked(handle, handle, policy):
        raise ValueError(
            "refusing to send: recipient is in contacts/blocked_chats.txt "
            "(the approval was consumed)"
        )
    # The phone showed payload.display_name. Anyone holding the helper token can
    # create approvals directly, so only honor the ones whose name is what this
    # helper would have written for that handle.
    if payload.get("display_name") != expected_display_name(handle, contacts) or not origin_is_honest(
        payload.get("contact_origin"), handle, contacts
    ):
        _gate_audit(ctx, "send_refused", approval_id=approval_id, detail={"reason": "display_name"})
        raise ValueError(
            "refusing to send: the approved name does not match your contacts for that "
            "recipient (the approval was consumed)"
        )
    _deliver_message(handle, text, service)
    _gate_audit(
        ctx,
        "send",
        handle=handle,
        approval_id=approval_id,
        detail={"via": "approval", "service": service, "text_length": len(text)},
    )
    return {
        "status": "sent",
        "sent": {
            **_agent_recipient_view(handle, contacts),
            "via": "approval",
            "approval_id": approval_id,
            "service": service,
            "text_length": len(text),
            "sent_at": datetime.now().isoformat(timespec="seconds"),
        },
    }


action_send_commit.needs_db = False  # type: ignore[attr-defined]


STANDARD_DURATIONS = ("1d", "1w")


def resolve_grant_request(params: dict[str, Any]) -> tuple[list[str], int | None, str | None]:
    """(scopes, duration_seconds, lookback) for request_grant.

    preset "trusted": permanent send + read (+ watch if asked), lookback default "all".
    preset "standard": send only, duration "1d" (default) or "1w".
    no preset: explicit scopes + duration; read/watch lookback defaults to "grant_time".
    The approver can still pick a different preset on their phone.
    """
    preset = params.get("preset")
    lookback = params.get("lookback")
    if lookback is not None and lookback not in LOOKBACKS:
        raise ValueError(f"lookback must be one of {LOOKBACKS}")
    if preset == "trusted":
        extra = validate_scopes(params["scopes"]) if params.get("scopes") else []
        scopes = sorted({"send", "read"} | ({"watch"} if "watch" in extra else set()))
        return scopes, None, lookback or "all"
    if preset == "standard":
        if lookback is not None:
            raise ValueError("the standard preset is send-only; request read separately")
        duration = params.get("duration") or "1d"
        if duration not in STANDARD_DURATIONS:
            raise ValueError(f"standard duration must be one of {STANDARD_DURATIONS}")
        return ["send"], parse_grant_duration(duration), None
    if preset is not None:
        raise ValueError("preset must be 'trusted' or 'standard'")
    scopes = validate_scopes(params.get("scopes"))
    duration = parse_grant_duration(params.get("duration"))
    history = any(s in ("read", "watch") for s in scopes)
    if lookback is not None and not history:
        raise ValueError("lookback only applies to read or watch")
    return scopes, duration, (lookback or "grant_time") if history else None


def action_request_grant(params, conn, contacts, privacy_policy):
    ctx, policy = _require_gate(privacy_policy)
    to = resolve_send_recipient(params, contacts)
    if is_blocked(to, to, policy):
        raise ValueError("refusing: contact is in contacts/blocked_chats.txt")
    scopes, duration, lookback = resolve_grant_request(params)
    handle = gate_handle(to)
    payload = {
        "handle": handle,
        "display_name": expected_display_name(handle, contacts),
        "scopes": scopes,
        "duration_seconds": duration,
        **_origin_fields(handle, contacts),
    }
    if lookback is not None:
        payload["lookback"] = lookback
    try:
        approval = _gate_call(ctx, ctx.client.create_approval, "grant", payload)
    except ctx.module.GateError as exc:
        raise _gate_request_error(exc) from None
    return {
        "status": "pending_approval",
        "approval_id": approval["id"],
        "approve_url": approval.get("approve_url"),
        "expires_at": approval.get("expires_at"),
        "recipient": _agent_recipient_view(handle, contacts),
        "scopes": scopes,
        "duration_seconds": duration,
        "lookback": lookback,
    }


action_request_grant.needs_db = False  # type: ignore[attr-defined]


def action_approval_status(params, conn, contacts, privacy_policy):
    ctx, _policy = _require_gate(privacy_policy)
    approval_id = ctx.module.validate_approval_id(params.get("approval_id"))
    try:
        data = _gate_call(ctx, ctx.client.get_approval, approval_id)
    except ctx.module.GateError as exc:
        if exc.status == 404:
            raise ValueError("unknown approval_id") from None
        raise _gate_request_error(exc) from None
    out = {
        "approval_id": data.get("id"),
        "kind": data.get("kind"),
        "status": data.get("status"),
        "expires_at": data.get("expires_at"),
        "decided_at": data.get("decided_at"),
    }
    if isinstance(data.get("grants"), list):
        out["grants"] = [
            {"grant_id": g.get("id"), "scope": g.get("scope"), "expires_at": g.get("expires_at")}
            for g in data["grants"]
            if isinstance(g, dict)
        ]
    return out


action_approval_status.needs_db = False  # type: ignore[attr-defined]
action_approval_status.needs_contacts = False  # type: ignore[attr-defined]


def _grant_view(grant: dict[str, Any], contacts: dict[str, str]) -> dict[str, Any] | None:
    key = _normalize_handle(grant["handle"])
    if not key:
        return None
    return {
        "grant_id": grant["id"],
        "scope": grant["scope"],
        "expires_at": grant["expires_at"],
        "lookback": grant.get("lookback"),
        "history_from": grant["history_floor"].isoformat()
        if grant.get("history_floor") is not None
        else None,
        "name": contacts.get(key) or unknown_sender_name(key),
        "label": contact_handle_label(key) or ("email" if "@" in key else "phone"),
        "service": _contact_refs.contact_service(key),
        "contact_ref": _contact_refs.make_contact_ref(key),
    }


def action_list_grants(params, conn, contacts, privacy_policy):
    _ctx, policy = _require_gate(privacy_policy)
    views = [v for v in (_grant_view(g, contacts) for g in policy.grants) if v]
    return {"count": len(views), "grants": views}


action_list_grants.needs_db = False  # type: ignore[attr-defined]


def action_revoke_grant(params, conn, contacts, privacy_policy):
    """Revoke by grant_id, or every active grant for a contact_ref (optionally one scope)."""
    ctx, policy = _require_gate(privacy_policy)
    grant_id = params.get("grant_id")
    ref = params.get("contact_ref")
    scope = params.get("scope")
    if (grant_id is None) == (ref is None):
        raise ValueError("provide grant_id or contact_ref")
    if scope is not None and scope not in GRANT_SCOPES:
        raise ValueError(f"scope must be one of {GRANT_SCOPES}")

    if grant_id is not None:
        if isinstance(grant_id, bool) or not isinstance(grant_id, int) or grant_id <= 0:
            raise ValueError("grant_id must be a positive integer")
        ids = [grant_id]
    else:
        if not isinstance(ref, str) or not ref.strip():
            raise ValueError("contact_ref must be a non-empty string")
        key = _contact_refs._hmac_key()
        ids = [
            g["id"]
            for g in policy.grants
            if (scope is None or g["scope"] == scope)
            and _normalize_handle(g["handle"])
            and hmac.compare_digest(
                _contact_refs.make_contact_ref(_normalize_handle(g["handle"]), key),
                ref.strip(),
            )
        ]
        if not ids:
            raise ValueError("no active grants match that contact_ref")

    revoked = []
    for gid in ids:
        try:
            result = _gate_call(ctx, ctx.client.revoke_grant, gid)
        except ctx.module.GateError as exc:
            if exc.status == 404:
                raise ValueError(f"unknown grant_id {gid}") from None
            raise _gate_request_error(exc) from None
        grant = result.get("grant") if isinstance(result, dict) else None
        revoked.append(
            {
                "grant_id": gid,
                "scope": grant.get("scope") if isinstance(grant, dict) else None,
                "newly_revoked": bool(result.get("revoked")) if isinstance(result, dict) else False,
            }
        )
    return {"revoked": revoked}


action_revoke_grant.needs_db = False  # type: ignore[attr-defined]
action_revoke_grant.needs_contacts = False  # type: ignore[attr-defined]


def _load_state_file(path: Path) -> dict[str, Any]:
    try:
        with _private_directory_fd(path.parent, create=True) as state_fd:
            try:
                fd = os.open(path.name, os.O_RDONLY | _FILE_NOFOLLOW_FLAGS, dir_fd=state_fd)
            except FileNotFoundError:
                return {}
            try:
                metadata = _validate_regular_file(fd, str(path), private=True)
                if metadata.st_size > _STATE_MAX_BYTES:
                    raise ValueError("state file too large")
                data = json.loads(os.read(fd, _STATE_MAX_BYTES + 1).decode("utf-8"))
            finally:
                os.close(fd)
    except (OSError, ValueError, UnsafeRuntimePath) as exc:
        log(f"state file {path.name} unreadable, resetting: {exc}")
        return {}
    return data if isinstance(data, dict) else {}


def _save_state_file(path: Path, state: dict[str, Any]) -> None:
    name = path.name
    tmp = f".{name}.{uuid.uuid4().hex}.tmp"
    with _private_directory_fd(path.parent, create=True) as state_fd:
        fd = os.open(
            tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW_FLAGS, 0o600, dir_fd=state_fd
        )
        try:
            _validate_regular_file(fd, tmp, private=True)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = -1
                json.dump(state, f)
            os.replace(tmp, name, src_dir_fd=state_fd, dst_dir_fd=state_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(tmp, dir_fd=state_fd)
            except FileNotFoundError:
                pass


def _load_watch_state() -> dict[str, Any]:
    return _load_state_file(WATCH_STATE_PATH)


def _save_watch_state(state: dict[str, Any]) -> None:
    _save_state_file(WATCH_STATE_PATH, state)


def _state_cursor(state: dict[str, Any], key: str) -> int | None:
    value = state.get(key)
    try:
        return _validate_cursor(value, key)
    except ValueError:
        return None


def _max_message_rowid(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COALESCE(MAX(ROWID), 0) FROM message").fetchone()
    return int(row[0] or 0)


def open_chatdb_direct() -> sqlite3.Connection:
    """Read-only connection to the live chat.db for small, cursor-bounded
    queries (inbox, watch_tick) where a full snapshot every minute would be
    wasteful. Nothing is written to disk."""
    if not CHAT_DB_PATH.exists():
        raise RuntimeError(f"chat.db not found at {CHAT_DB_PATH}")
    uri = f"{CHAT_DB_PATH.resolve().as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    conn.text_factory = bytes
    return conn


_WATCH_TICK_SQL = """
    SELECT m.ROWID, c.chat_identifier, COALESCE(h.id, ''), m.date
    FROM message m
    JOIN chat_message_join cmj ON cmj.message_id = m.ROWID
    JOIN chat c ON c.ROWID = cmj.chat_id
    LEFT JOIN handle h ON h.ROWID = m.handle_id
    WHERE m.ROWID > ? AND m.ROWID <= ? AND m.is_from_me = 0
    ORDER BY m.ROWID ASC
    LIMIT ?
"""


def action_watch_tick(params, conn, contacts, privacy_policy):
    """Content-free: how many new inbound messages from watched contacts
    arrived since the last tick. The cursor lives in bridge state."""
    _ctx, policy = _require_gate(privacy_policy)
    watch_policy = scoped_policy(policy, "watch")
    state = _load_watch_state()
    cursor = _state_cursor(state, "tick_cursor")
    max_rowid = _max_message_rowid(conn)
    if cursor is None or cursor > max_rowid:
        state["tick_cursor"] = max_rowid
        _save_watch_state(state)
        return {"new_count": 0, "initialized": True, "capped": False}

    rows = conn.execute(_WATCH_TICK_SQL, (cursor, max_rowid, WATCH_TICK_SCAN_LIMIT)).fetchall()
    count = 0
    seen: set[int] = set()
    for rowid, chat_id, sender, date_ns in rows:
        if rowid in seen:
            continue
        chat_id, sender = _decode_db_text(chat_id), _decode_db_text(sender)
        if is_read_allowed(chat_id, sender, watch_policy) and history_floor_ok(
            chat_id, date_ns, watch_policy, "watch"
        ):
            seen.add(rowid)
            count += 1
    capped = len(rows) == WATCH_TICK_SCAN_LIMIT
    state["tick_cursor"] = int(rows[-1][0]) if capped else max_rowid
    _save_watch_state(state)
    return {"new_count": count, "initialized": False, "capped": capped}


action_watch_tick.db_mode = "direct"  # type: ignore[attr-defined]
action_watch_tick.needs_contacts = False  # type: ignore[attr-defined]


_INBOX_SQL = """
    SELECT m.ROWID, c.chat_identifier, c.style, m.date, COALESCE(h.id, ''),
           m.text, m.attributedBody
    FROM message m
    JOIN chat_message_join cmj ON cmj.message_id = m.ROWID
    JOIN chat c ON c.ROWID = cmj.chat_id
    LEFT JOIN handle h ON h.ROWID = m.handle_id
    WHERE m.ROWID > ? AND m.ROWID <= ? AND m.is_from_me = 0 AND m.date > ?
    ORDER BY m.ROWID ASC
    LIMIT ?
"""


def action_inbox(params, conn, contacts, privacy_policy):
    """New inbound messages from watch-scoped contacts, newest cursor last.

    Without `cursor` the helper resumes from its own saved inbox cursor (first
    run: the last 24 hours) and advances it. Senders appear as name, label,
    and contact_ref, never as raw handles.
    """
    _ctx, policy = _require_gate(privacy_policy)
    watch_policy = scoped_policy(policy, "watch")
    limit = int(_as_number(params.get("limit", 50), "limit"))
    if limit <= 0 or limit > MAX_INBOX_LIMIT:
        raise ValueError(f"limit must be in (0, {MAX_INBOX_LIMIT}]")

    explicit = params.get("cursor")
    state = _load_watch_state() if explicit is None else {}
    since_ns = 0
    if explicit is not None:
        cursor = _validate_cursor(explicit)
    else:
        saved = _state_cursor(state, "inbox_cursor")
        if saved is None:
            cursor = 0
            since_ns = to_apple_ns(time.time() - INBOX_FIRST_RUN_HOURS * 3600)
        else:
            cursor = saved
    # Nothing older than the oldest watch grant is ever eligible (see
    # history_floor_ok), so don't scan it either — even from cursor 0.
    floors = list(policy.watch_since.values())
    if policy.unknown_enabled:
        floors.append(policy.unknown_floor)
    if floors and None not in floors:
        since_ns = max(since_ns, min(floors) - 1)

    max_rowid = _max_message_rowid(conn)
    rows = (
        conn.execute(_INBOX_SQL, (cursor, max_rowid, since_ns, INBOX_SCAN_LIMIT)).fetchall()
        if policy.watch or policy.unknown_enabled
        else []
    )
    messages: list[dict[str, Any]] = []
    next_cursor = cursor
    filled = False
    seen: set[int] = set()
    for rowid, chat_id, style, date_ns, sender, text, attrib in rows:
        next_cursor = int(rowid)
        chat_id = _decode_db_text(chat_id)
        sender = _decode_db_text(sender)
        if (
            rowid in seen
            or not is_read_allowed(chat_id, sender, watch_policy)
            or not history_floor_ok(chat_id, date_ns, watch_policy, "watch")
        ):
            continue
        seen.add(rowid)
        body = _decode_db_text(text)
        if not body and attrib:
            body = decode_attributed_body(attrib)
        item = {
            "message_id": int(rowid),
            "ts": from_apple_ns(date_ns).isoformat(timespec="seconds"),
            **person_view(sender or chat_id, contacts),
            "is_group": _chat_kind(chat_id, style) == "group",
            "text": redact(body)[:MAX_TEXT_SNIPPET],
        }
        if item["is_group"]:
            item["thread_ref"] = thread_ref(chat_id)
        messages.append(item)
        if len(messages) >= limit:
            filled = True
            break

    has_more = filled or len(rows) == INBOX_SCAN_LIMIT
    if not has_more:
        next_cursor = max(next_cursor, max_rowid)
    if explicit is None:
        state["inbox_cursor"] = next_cursor
        _save_watch_state(state)
    return {
        "cursor": cursor,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "count": len(messages),
        "messages": messages,
    }


action_inbox.db_mode = "direct"  # type: ignore[attr-defined]


MAX_CONTACT_NAME_LEN = 100


def validate_contact_name(v: Any) -> str:
    if not isinstance(v, str):
        raise ValueError("name must be a string")
    name = v.strip()
    if not name or len(name) > MAX_CONTACT_NAME_LEN:
        raise ValueError(f"name must be 1..{MAX_CONTACT_NAME_LEN} characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name) or _INVISIBLE_CONTROLS_RE.search(name):
        raise ValueError("name contains control or invisible characters")
    if "@" in name or len(re.sub(r"\D", "", name)) >= 7:
        raise ValueError("name must not contain a phone number or email address")
    return name


def _save_contact_script(name: str, handle: str) -> str:
    first, _, last = name.partition(" ")
    kind = "email" if "@" in handle else "phone"
    label = "home" if kind == "email" else "mobile"
    note = f"{GROK_ADDED_MARKER} on {datetime.now().date().isoformat()}."
    esc = _escape_as_string
    return (
        'tell application "Contacts"\n'
        f'    set p to make new person with properties {{first name:"{esc(first)}", '
        f'last name:"{esc(last)}", note:"{esc(note)}"}}\n'
        f'    make new {kind} at end of {kind}s of p with properties '
        f'{{label:"{label}", value:"{esc(handle)}"}}\n'
        "    save\n"
        f'    if not (exists group "{esc(GROK_CONTACTS_GROUP)}") then\n'
        f'        make new group with properties {{name:"{esc(GROK_CONTACTS_GROUP)}"}}\n'
        "        save\n"
        "    end if\n"
        f'    add p to group "{esc(GROK_CONTACTS_GROUP)}"\n'
        "    save\n"
        "end tell\n"
    )


def action_save_contact(params, conn, contacts, privacy_policy):
    """Create a new Contacts entry for an unsaved 1:1 handle.

    Never edits or overwrites: refuses handles already in Contacts. Grants
    nothing. The note marker and group make the entry visibly Grok-created,
    and approvals for it are flagged "added by Grok" on the phone.
    """
    ctx, policy = _require_gate(privacy_policy)
    if params.get("to") is not None:
        raise ValueError("save_contact takes thread_ref or contact_ref")
    name = validate_contact_name(params.get("name"))
    raw = resolve_send_recipient(
        {k: params[k] for k in ("contact_ref", "thread_ref") if params.get(k) is not None}, contacts
    )
    handle = gate_handle(raw)
    key = _normalize_handle(handle)
    if key in contacts:
        raise ValueError("that person is already in Contacts; Grok can't edit existing contacts")
    rc, stdout, stderr = _run_osascript(_save_contact_script(name, handle))
    if rc != 0:
        log(f"save_contact osascript failed (rc={rc}): {stderr or stdout or 'no output'}")
        raise RuntimeError(
            f"Contacts could not save the entry (osascript rc={rc}); the helper may need "
            "permission to control Contacts (System Settings → Privacy & Security → Automation)"
        )
    registry = _load_state_file(GROK_ADDED_PATH)
    handles = [h for h in registry.get("handles", []) if isinstance(h, str)]
    if handle not in handles:
        handles.append(handle)
    _save_state_file(GROK_ADDED_PATH, {"handles": handles[-1000:]})
    _gate_audit(ctx, "contact_saved", handle=handle, detail={"name_length": len(name)})
    return {
        "saved": {
            "name": name,
            "label": "email" if "@" in key else "mobile",
            "contact_ref": _contact_refs.make_contact_ref(key),
            "added_by_grok": True,
            "grants": "none: saving a contact grants nothing",
        }
    }


action_save_contact.needs_db = False  # type: ignore[attr-defined]


ACTIONS = {
    "status": action_status,
    "review": action_review,
    "search": action_search,
    "chat_history": action_chat_history,
    "response_stats": action_response_stats,
    "contacts_lookup": action_contacts_lookup,
    "list_chats": action_list_chats,
    "send_preview": action_send_preview,
    "send": action_send,
    "send_commit": action_send_commit,
    "request_grant": action_request_grant,
    "approval_status": action_approval_status,
    "list_grants": action_list_grants,
    "revoke_grant": action_revoke_grant,
    "inbox": action_inbox,
    "watch_tick": action_watch_tick,
    "save_contact": action_save_contact,
}


# ---------------------------------------------------------------------------
# Request / response plumbing
# ---------------------------------------------------------------------------
def write_response(req_filename_stem: str, data: dict) -> None:
    """Write response JSON atomically. Uses the request filename stem to
    derive the response filename, never trusting JSON id for the path.
    """
    if not req_filename_stem or "/" in req_filename_stem or req_filename_stem in (".", ".."):
        raise ValueError("invalid response filename stem")
    name = f"response-{req_filename_stem}.json"
    tmp = f".{name}.{uuid.uuid4().hex}.tmp"
    with _private_directory_fd(RESPONSES_DIR, create=True) as responses_fd:
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW_FLAGS,
            0o600,
            dir_fd=responses_fd,
        )
        try:
            _validate_regular_file(fd, tmp, private=True)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = -1
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, name, src_dir_fd=responses_fd, dst_dir_fd=responses_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(tmp, dir_fd=responses_fd)
            except FileNotFoundError:
                pass


def reap_expired_responses() -> None:
    """Remove response payloads that the host failed to consume promptly."""
    now = time.time()
    try:
        with _private_directory_fd(RESPONSES_DIR) as responses_fd:
            for name in os.listdir(responses_fd):
                if not (name.startswith("response-") and name.endswith(".json")):
                    continue
                try:
                    # Legacy releases may have left broader file modes. The
                    # containing directory is private; unlinking a verified
                    # regular, current-user-owned file does not follow it.
                    metadata = _stat_regular_at(responses_fd, name)
                    if now - metadata.st_mtime > RESPONSE_TTL_S:
                        os.unlink(name, dir_fd=responses_fd)
                except (OSError, UnsafeRuntimePath) as e:
                    log(f"response reaper could not remove {name}: {e}")
    except UnsafeRuntimePath as e:
        if isinstance(e.__cause__, FileNotFoundError):
            return
        raise


def _read_request_text(req_path: Path, requests_fd: int | None) -> str:
    if requests_fd is None:
        fd = os.open(req_path, os.O_RDONLY | _FILE_NOFOLLOW_FLAGS)
    else:
        fd = os.open(
            req_path.name,
            os.O_RDONLY | _FILE_NOFOLLOW_FLAGS,
            dir_fd=requests_fd,
        )
    try:
        metadata = _validate_regular_file(fd, str(req_path))
        if metadata.st_size > MAX_REQUEST_BYTES:
            raise ValueError(f"request exceeds {MAX_REQUEST_BYTES} byte limit")
        chunks: list[bytes] = []
        remaining = MAX_REQUEST_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError(f"request exceeds {MAX_REQUEST_BYTES} byte limit")
        return raw.decode("utf-8")
    finally:
        os.close(fd)


def _bad_request(req_stem: str, error: str, *, req_id: str | None = None) -> None:
    response: dict[str, Any] = {"ok": False, "error": error,
                                "allowed_actions": sorted(allowed_actions())}
    if req_id is not None:
        response["id"] = req_id
    write_response(req_stem, response)


def process_request(
    req_path: Path,
    privacy_policy: PrivacyPolicy | list[str],
    *,
    requests_fd: int | None = None,
) -> None:
    # Derive safe response filename from request filename stem only.
    # Never use JSON id field for filesystem paths — it could contain slashes.
    req_stem = req_path.stem.replace("request-", "")
    if not req_stem:
        log(f"skipping malformed request filename: {req_path.name}")
        return

    # Ignore incomplete files: *.tmp, *.partial, names starting with .
    if (req_path.suffix in (".tmp", ".partial") or
        req_path.name.startswith(".") or
        req_path.name.startswith("request-") and not req_path.name.endswith(".json")):
        return

    try:
        raw = _read_request_text(req_path, requests_fd)
    except Exception as e:
        _bad_request(req_stem, f"bad request file: {e}")
        return
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Preserve compatibility with non-atomic clients by retrying malformed
        # JSON once. Secure descriptor-relative opens still reject symlinks.
        time.sleep(0.1)
        try:
            raw = _read_request_text(req_path, requests_fd)
            data = json.loads(raw)
        except Exception as e:
            _bad_request(req_stem, f"bad request JSON: {e}")
            return

    if not isinstance(data, dict):
        _bad_request(req_stem, "bad request: JSON root must be an object")
        return

    # Echo back the JSON id in response, but never use it for filesystem paths.
    req_id = str(data.get("id", req_stem))
    action = data.get("action")
    params = data.get("params", {})

    if not isinstance(action, str):
        _bad_request(req_stem, "bad request: action must be a string", req_id=req_id)
        return
    if not isinstance(params, dict):
        _bad_request(req_stem, "bad request: params must be an object", req_id=req_id)
        return

    permitted = allowed_actions()
    if action not in ACTIONS:
        write_response(req_stem, {
            "id": req_id,
            "ok": False,
            "error": f"unknown action: {action!r}",
            "allowed_actions": sorted(permitted),
        })
        return
    if action not in permitted:
        # Role gate: enforced here in the worker, never only in a host or
        # app layer. A manager bridge never serves bodies; a host bridge
        # never enumerates chats.
        write_response(req_stem, {
            "id": req_id,
            "ok": False,
            "error": "action not permitted on this bridge",
            "bridge_role": bridge_role(),
            "allowed_actions": sorted(permitted),
        })
        return

    conn = None
    try:
        action_fn = ACTIONS[action]
        # Send-side actions declare needs_db=False; skip the (potentially
        # hundreds-of-MB) chat.db snapshot on that path.
        needs_db = getattr(action_fn, "needs_db", True)
        if needs_db:
            if getattr(action_fn, "db_mode", "snapshot") == "direct":
                conn = open_chatdb_direct()
            else:
                conn = copy_chatdb()
        needs_contacts = getattr(action_fn, "needs_contacts", True)
        contacts = load_contacts() if needs_contacts else {}
        result = action_fn(params, conn, contacts, privacy_policy)
        if conn is not None:
            conn.close()
        result.update({"id": req_id, "action": action, "ok": True,
                       "generated_at": datetime.now().isoformat(timespec="seconds")})
        write_response(req_stem, result)
    except Exception as e:
        log(f"action={action} id={req_id} error: {e!r}")
        log(traceback.format_exc())
        write_response(req_stem, {
            "id": req_id, "action": action, "ok": False, "error": scrub_handles(str(e)),
            "allowed_actions": sorted(permitted),
        })
    finally:
        if conn is not None:
            conn.close()


def _acquire_bridge_lock(control_fd: int, timeout_s: float = OSASCRIPT_TIMEOUT_S + 10.0) -> int:
    """Acquire an exclusive lock on control/lock with bounded wait.

    Returns the lock file descriptor on success. The caller must close it
    to release the lock. Raises RuntimeError on timeout or failure.
    """
    open_deadline = time.time() + timeout_s
    while True:
        try:
            lock_fd = os.open(
                "lock",
                os.O_CREAT | os.O_RDWR | _FILE_NOFOLLOW_FLAGS,
                0o600,
                dir_fd=control_fd,
            )
            break
        except FileNotFoundError:
            if time.time() >= open_deadline:
                message = "could not create bridge lock file"
                log(message)
                raise RuntimeError(message)
            time.sleep(0.01)
        except OSError as exc:
            message = f"could not open bridge lock file: {exc}"
            log(message)
            raise RuntimeError(message) from exc
    try:
        _validate_regular_file(lock_fd, "control/lock", private=True)
    except Exception as exc:
        os.close(lock_fd)
        message = f"unsafe bridge lock file: {exc}"
        log(message)
        raise RuntimeError(message) from exc

    # Try non-blocking lock first
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock_fd
    except (OSError, BlockingIOError):
        pass

    # Lock is held; poll with bounded wait
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(0.05)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock_fd
        except (OSError, BlockingIOError):
            continue

    message = (
        f"could not acquire bridge lock within {timeout_s}s timeout; "
        "another worker is processing this bridge"
    )
    log(message)
    os.close(lock_fd)
    raise RuntimeError(message)


def main() -> None:
    for path in (LOG_PATH.parent, REQUESTS_DIR, RESPONSES_DIR):
        with _private_directory_fd(path, create=True):
            pass

    reap_expired_responses()

    # v0.4.0+: garbage-collect stale send nonces from previews that never
    # got a matching send (user cancelled, the host stopped before sending). Cheap; touches
    # only ~/imessage-bridge/nonces/ and only a few files at most.
    # Manager role: skip nonce reaping (no nonces directory created).
    if bridge_role() != "manager":
        try:
            reap_expired_nonces()
        except Exception as e:
            log(f"reap_expired_nonces error: {e!r}")

    # Acquire per-bridge advisory lock to serialize workers on this bridge.
    # Hold for the entire drain; re-list requests once after acquiring to
    # catch any that arrived during the lock wait. The lock is released
    # automatically when lock_fd is closed on exit.
    try:
        with _private_directory_fd(LOG_PATH.parent) as control_fd:
            lock_fd = _acquire_bridge_lock(control_fd)
    except RuntimeError as e:
        log(f"bridge lock unavailable, deferring drain: {e}")
        return

    try:
        # Only process complete request files (*.json, not temp/partial suffixes).
        with _private_directory_fd(REQUESTS_DIR) as requests_fd:
            pending = sorted(
                name
                for name in os.listdir(requests_fd)
                if name.startswith("request-") and name.endswith(".json")
            )
            if not pending:
                # launchd sometimes fires with no new file (e.g. directory-touch).
                return

            for name in pending:
                request = Path(name)
                req_stem = request.stem.replace("request-", "")
                try:
                    # Per request, so a revoke or expiry applies to requests
                    # already queued in this drain.
                    process_request(request, load_privacy_policy(), requests_fd=requests_fd)
                except Exception as e:
                    log(f"request={name} unhandled error: {e!r}")
                    try:
                        _bad_request(req_stem, f"request processing failed: {e}")
                    except Exception as response_error:
                        log(f"request={name} could not write error response: {response_error!r}")
                finally:
                    try:
                        os.unlink(name, dir_fd=requests_fd)
                    except Exception as e:
                        log(f"could not unlink {name}: {e}")
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    main()
