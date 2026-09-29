#!/usr/bin/env python3
"""Diagnose a Grok Bot iMessage helper installation without reading messages."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
from typing import Any


def check(status: str, detail: str) -> dict[str, str]:
    return {"status": status, "detail": detail}


def mode(path: pathlib.Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def absolute_path_preserving_dotdot(path: pathlib.Path) -> pathlib.Path:
    expanded = path.expanduser()
    return expanded if expanded.is_absolute() else pathlib.Path.cwd() / expanded


def has_symlink_component(path: pathlib.Path) -> bool:
    absolute = absolute_path_preserving_dotdot(path)
    current = pathlib.Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def worker_images(interpreter: pathlib.Path) -> list[pathlib.Path]:
    """The baked interpreter plus the image it re-execs into: framework
    launchers (Versions/X.Y/bin/pythonX.Y) exec Resources/Python.app, and
    that process is the one holding the gate secrets."""
    images = [interpreter]
    if interpreter.parent.name == "bin" and interpreter.name.startswith("python"):
        app = interpreter.parent.parent / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
        if app.is_file():
            images.append(app)
    return images


def python_attach_checks(code_root: pathlib.Path, *, skip_codesign: bool) -> dict[str, dict[str, str]]:
    """The worker holds the gate secrets as an ordinary user process, so the
    images it actually runs must not be debuggable by the user."""
    out: dict[str, dict[str, str]] = {}
    record = code_root / "python-interpreter"
    wrapper = code_root / "bin" / "grokbot-imessage-helper"
    try:
        baked = pathlib.Path(record.read_text(encoding="utf-8").strip())
    except OSError:
        return {"python_not_debuggable": check("fail", f"{record} missing; reinstall")}
    in_wrapper = wrapper.is_file() and str(baked).encode() in wrapper.read_bytes()
    shim = str(baked).startswith("/usr/bin/")
    out["python_interpreter_baked"] = check(
        "pass" if in_wrapper and not shim and baked.is_file() else "fail",
        f"{baked} in_wrapper={in_wrapper} xcrun_shim={shim}",
    )
    if not skip_codesign:
        details = []
        ok = True
        for image in worker_images(baked):
            info = run(["/usr/bin/codesign", "-dv", "--verbose=4", str(image)])
            ents = run(["/usr/bin/codesign", "-d", "--entitlements", "-", str(image)])
            text = (info.stderr or "") + (info.stdout or "")
            apple = "Authority=Software Signing" in text or "Platform identifier" in text
            debuggable = "get-task-allow" in ((ents.stdout or "") + (ents.stderr or ""))
            hardened = "(runtime)" in text
            ok = ok and apple and not debuggable
            details.append(f"{image} apple={apple} get_task_allow={debuggable} hardened_runtime={hardened}")
        out["python_not_debuggable"] = check("pass" if ok else "fail", "; ".join(details))
    devtools = run(["/usr/sbin/DevToolsSecurity", "-status"])
    enabled = "enabled" in (devtools.stdout or "").lower() and "disabled" not in (devtools.stdout or "").lower()
    out["developer_mode_off"] = check(
        "warn" if enabled else "pass",
        "Developer mode is on: debuggers may attach to the helper's Python" if enabled else "Developer mode is off",
    )
    return out


def helper_status(bridge: pathlib.Path, timeout_s: float = 15.0) -> dict[str, Any] | None:
    """Ask the running helper for `status` through the bridge (it has FDA; we don't)."""
    import time
    import uuid

    rid = f"doctor-{uuid.uuid4().hex[:12]}"
    requests = bridge / "control" / "requests"
    response = bridge / "control" / "responses" / f"response-{rid}.json"
    tmp = requests / f".request-{rid}.json.tmp"
    try:
        tmp.write_text(json.dumps({"id": rid, "action": "status", "params": {}}))
        tmp.replace(requests / f"request-{rid}.json")
    except OSError:
        return None
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if response.is_file():
            try:
                return json.loads(response.read_text())
            except (OSError, ValueError):
                return None
            finally:
                response.unlink(missing_ok=True)
        time.sleep(0.25)
    (requests / f"request-{rid}.json").unlink(missing_ok=True)
    return None


def contacts_marker_check(bridge: pathlib.Path) -> dict[str, dict[str, str]]:
    status = helper_status(bridge)
    gate = (status or {}).get("gate") or {}
    health = gate.get("contacts")
    if not isinstance(health, dict):
        return {"grok_marker_detected": check("warn", "helper didn't answer status (FDA granted? gate mode on?)")}
    if gate.get("reachable") is not True:
        # Contacts load with the gate policy, so there is nothing to judge yet.
        return {"grok_marker_detected": check("warn", "approval gate unreachable; rerun doctor once it answers")}
    ok = health.get("notes_readable") is True and health.get("grok_recorded_missing_marker", 1) == 0
    return {
        "grok_marker_detected": check(
            "pass" if ok else "fail",
            f"contacts_loaded={health.get('loaded')} notes_readable={health.get('notes_readable')} "
            f"marked={health.get('grok_marked')} recorded_without_marker={health.get('grok_recorded_missing_marker')}",
        )
    }


def inspect_install(args: argparse.Namespace) -> dict[str, Any]:
    bridge = absolute_path_preserving_dotdot(args.bridge)
    code_root = absolute_path_preserving_dotdot(args.code_root or bridge)
    hardened = code_root != bridge
    expected_code_uid = 0 if hardened else os.getuid()
    checks: dict[str, dict[str, str]] = {}

    bridge_ok = (
        bridge.is_dir()
        and not has_symlink_component(bridge)
        and bridge.stat().st_uid == os.getuid()
        and mode(bridge) & 0o077 == 0
    )
    checks["bridge_root"] = check(
        "pass" if bridge_ok else "fail",
        f"{bridge} uid={bridge.stat().st_uid if bridge.exists() else 'missing'} "
        f"mode={oct(mode(bridge)) if bridge.exists() else 'missing'}",
    )

    code_ok = (
        code_root.is_dir()
        and not has_symlink_component(code_root)
        and code_root.stat().st_uid == expected_code_uid
        and mode(code_root) & 0o022 == 0
    )
    checks["code_root"] = check(
        "pass" if code_ok else "fail",
        f"{code_root} uid={code_root.stat().st_uid if code_root.exists() else 'missing'} "
        f"mode={oct(mode(code_root)) if code_root.exists() else 'missing'}",
    )

    directory_modes = {
        "requests_dir": bridge / "control" / "requests",
        "responses_dir": bridge / "control" / "responses",
        "contacts_dir": bridge / "contacts",
    }
    for name, path in directory_modes.items():
        ok = (
            path.is_dir()
            and not has_symlink_component(path)
            and mode(path) & 0o077 == 0
        )
        checks[name] = check("pass" if ok else "fail", f"{path} mode={oct(mode(path)) if path.exists() else 'missing'}")

    executable_files = {
        "fda_wrapper": code_root / "bin" / "grokbot-imessage-helper",
        "confirmation_helper": code_root / "bin" / "grokbot-imessage-confirm",
    }
    for name, path in executable_files.items():
        allowed_mode = 0o555 if hardened else 0o700
        if hardened and name == "fda_wrapper":
            allowed_mode = 0o4555  # setuid root to read the root-only gate.json
        ok = (
            path.is_file()
            and not has_symlink_component(path)
            and os.access(path, os.X_OK)
            and path.stat().st_uid == expected_code_uid
            and mode(path) == allowed_mode
        )
        checks[name] = check("pass" if ok else "fail", str(path))

    protected_files = {
        "helper_source": (code_root / "bin" / "helper.py", 0o444 if hardened else 0o500),
        "send_gate_source": (code_root / "bin" / "send_gate.py", 0o444 if hardened else 0o500),
        "blocklist": (bridge / "contacts" / "blocked_chats.txt", 0o600),
        "log": (bridge / "control" / "log.txt", 0o600),
        "read_policy": (bridge / "contacts" / "read_policy.txt", 0o600),
    }
    if hardened:
        protected_files["gate_client_source"] = (code_root / "bin" / "gate_client.py", 0o444)
    for name, (path, expected) in protected_files.items():
        expected_uid = expected_code_uid if name.endswith("source") else os.getuid()
        ok = (
            path.is_file()
            and not has_symlink_component(path)
            and path.stat().st_uid == expected_uid
            and mode(path) == expected
        )
        detail = f"{path} mode={oct(mode(path)) if path.exists() else 'missing'} expected={oct(expected)}"
        checks[name] = check("pass" if ok else "fail", detail)

    allowlist = (
        code_root.parent / "config" / "allowed_chats.txt"
        if hardened
        else bridge / "contacts" / "allowed_chats.txt"
    )
    expected_allowlist_uid = 0 if hardened else os.getuid()
    expected_allowlist_mode = 0o600
    allowlist_ok = (
        allowlist.is_file()
        and not has_symlink_component(allowlist)
        and allowlist.stat().st_uid == expected_allowlist_uid
        and mode(allowlist) == expected_allowlist_mode
        and os.access(allowlist, os.R_OK)
    )
    checks["read_allowlist"] = check(
        "pass" if allowlist_ok else "fail",
        f"{allowlist} uid={allowlist.stat().st_uid if allowlist.exists() else 'missing'} "
        f"mode={oct(mode(allowlist)) if allowlist.exists() else 'missing'}",
    )

    if hardened:
        # Root-only secrets: readable by the setuid wrapper, never by this user.
        gate_json = code_root.parent / "config" / "gate.json"
        gate_ok = (
            gate_json.is_file()
            and not has_symlink_component(gate_json)
            and gate_json.stat().st_uid == 0
            and gate_json.stat().st_nlink == 1
            and mode(gate_json) == 0o600
            and not os.access(gate_json, os.R_OK)
        )
        checks["gate_config_root_only"] = check(
            "pass" if gate_ok else "fail",
            f"{gate_json} mode={oct(mode(gate_json)) if gate_json.exists() else 'missing'} "
            f"readable_by_user={os.access(gate_json, os.R_OK) if gate_json.exists() else 'n/a'}",
        )

        # A hard link to the setuid wrapper would outlive reinstalls.
        wrapper = executable_files["fda_wrapper"]
        links = wrapper.stat().st_nlink if wrapper.exists() else 0
        checks["fda_wrapper_single_link"] = check(
            "pass" if links == 1 else "fail", f"{wrapper} st_nlink={links} (expected 1)"
        )
        checks.update(python_attach_checks(code_root, skip_codesign=args.skip_codesign))
        if not args.skip_chat_db:
            checks.update(contacts_marker_check(bridge))

    if not args.skip_codesign:
        for name, path in executable_files.items():
            result = run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(path)])
            checks[f"{name}_signature"] = check(
                "pass" if result.returncode == 0 else "fail",
                (result.stderr or result.stdout or "signature valid").strip(),
            )

    if not args.skip_launchd:
        launchctl = shutil.which("launchctl")
        if launchctl is None:
            checks["launchd"] = check("fail", "launchctl not found")
        else:
            uid = os.getuid()
            result = run([launchctl, "print", f"gui/{uid}/com.jeffhuber.grokbot-imessage"])
            checks["launchd"] = check(
                "pass" if result.returncode == 0 else "fail",
                "LaunchAgent loaded" if result.returncode == 0 else "LaunchAgent not loaded",
            )
            watch = run([launchctl, "print", f"gui/{uid}/com.jeffhuber.grokbot-imessage-watch"])
            checks["watch_launchd"] = check(
                "pass" if watch.returncode == 0 else "fail",
                "watch LaunchAgent loaded" if watch.returncode == 0 else "watch LaunchAgent not loaded",
            )
            if hardened:
                power_nap_label = f"com.jeffhuber.grokbot-imessage-power-nap.{uid}"
                power_nap = run([launchctl, "print", f"system/{power_nap_label}"])
                checks["power_nap_launchd"] = check(
                    "pass" if power_nap.returncode == 0 else "fail",
                    f"{power_nap_label} loaded"
                    if power_nap.returncode == 0
                    else f"{power_nap_label} not loaded",
                )
                script = code_root / "tools" / "power_nap_tick.sh"
                script_ok = (
                    script.is_file()
                    and not has_symlink_component(script)
                    and script.stat().st_uid == 0
                    and mode(script) == 0o555
                )
                checks["power_nap_script"] = check(
                    "pass" if script_ok else "fail",
                    str(script),
                )
                pmset = run(["/usr/bin/pmset", "-g", "ps"])
                on_ac = "AC Power" in (pmset.stdout or "")
                sched = run(["/usr/bin/pmset", "-g", "sched"])
                owned = [
                    line.strip()
                    for line in (sched.stdout or "").splitlines()
                    if f"by '{power_nap_label}'" in line
                ]
                if on_ac:
                    checks["power_nap_wake_schedule"] = check(
                        "pass" if owned else "warn",
                        owned[0] if owned else "no pmset wake scheduled on AC",
                    )
                else:
                    checks["power_nap_wake_schedule"] = check(
                        "pass" if not owned else "warn",
                        "on battery; no wake expected"
                        if not owned
                        else f"wake still scheduled on battery: {owned[0]}",
                    )

    if not args.skip_chat_db:
        chat_db = pathlib.Path.home() / "Library" / "Messages" / "chat.db"
        ok = chat_db.is_file() and os.access(chat_db, os.R_OK)
        checks["chat_db"] = check(
            "warn",
            (
                f"{chat_db} readable to this doctor process; this does not test "
                "wrapper FDA. Run the smoke test to verify wrapper access"
                if ok
                else f"{chat_db} not readable to this doctor process; this does not "
                "test wrapper FDA. Run the smoke test to verify wrapper access"
            ),
        )

    if not args.skip_grok:
        grok = shutil.which("grok")
        if grok is None:
            checks["grok_skill"] = check("fail", "grok CLI not found")
        else:
            result = run([grok, "inspect"])
            discovered = result.returncode == 0 and "imessage-grok-bot" in result.stdout
            checks["grok_skill"] = check(
                "pass" if discovered else "fail",
                "skill discovered" if discovered else "grok inspect did not report imessage-grok-bot",
            )

    return {
        "ok": all(value["status"] != "fail" for value in checks.values()),
        "architecture": "hardened" if hardened else "standard",
        "bridge": str(bridge),
        "code_root": str(code_root),
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge", required=True, type=pathlib.Path)
    parser.add_argument("--code-root", type=pathlib.Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--skip-grok", action="store_true")
    parser.add_argument("--skip-launchd", action="store_true")
    parser.add_argument("--skip-codesign", action="store_true")
    parser.add_argument("--skip-chat-db", action="store_true")
    args = parser.parse_args()

    report = inspect_install(args)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for name, result in report["checks"].items():
            print(f"[{result['status'].upper():4}] {name}: {result['detail']}")
        has_warnings = any(
            result["status"] == "warn" for result in report["checks"].values()
        )
        overall = (
            "healthy with warnings"
            if report["ok"] and has_warnings
            else "healthy" if report["ok"] else "attention required"
        )
        print("\nOverall:", overall)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
