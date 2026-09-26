"""H1: gate.json stays root-only; the setuid wrapper passes it over a pipe.

The real install is setuid root with a root-owned gate.json. These tests build
the same wrapper with GATE_SECRETS_OWNER_UID set to the test user, so the
privileged code path runs end to end without sudo. The only difference is
that setuid()/setgid() don't change identity here.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests._helper_loader import REPO_ROOT, helper

_spec = importlib.util.spec_from_file_location("contact_refs_fd", REPO_ROOT / "bin" / "contact_refs.py")
contact_refs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(contact_refs)

GATE = {"schema_version": 1, "contact_ref_hmac_key": "k" * 43, "gate_url": "https://g.test", "helper_token": "t" * 43}

PROBE = """
import json, os, resource, stat, sys
fd = int(os.environ["IMESSAGE_GATE_SECRETS_FD"])
st = os.fstat(fd)
data = b""
while True:
    chunk = os.read(fd, 4096)
    if not chunk:
        break
    data += chunk
print(json.dumps({
    "fd": fd,
    "is_pipe": stat.S_ISFIFO(st.st_mode),
    "content": data.decode(),
    "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(), "egid": os.getegid(),
    "gate_path": os.environ.get("IMESSAGE_GATE_PATH"),
    "core_limit": list(resource.getrlimit(resource.RLIMIT_CORE)),
}))
"""


@unittest.skipUnless(shutil.which("clang"), "clang required")
class WrapperSecretsFdTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="grokbot-h1-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.gate = self.root / "gate.json"
        self.gate.write_text(json.dumps(GATE))
        self.gate.chmod(0o600)

    def build(self, owner_uid: int | None = None, expected_user: int | None = None) -> Path:
        root = self.root
        helper_script = root / "helper.py"
        helper_script.write_text(PROBE)
        send_gate = root / "send_gate.py"
        send_gate.write_text("# fixture\n")
        confirm = root / "confirm"
        confirm.write_text("#!/bin/sh\nexit 0\n")
        for path, mode in ((helper_script, 0o500), (send_gate, 0o500), (confirm, 0o700)):
            path.chmod(mode)
        wrapper = root / f"wrapper-{owner_uid}-{expected_user}"
        uid = os.getuid() if owner_uid is None else owner_uid
        user = os.getuid() if expected_user is None else expected_user
        result = subprocess.run(
            [
                "clang", "-Wall", "-Wextra", "-Werror", "-O2",
                f'-DHELPER_SCRIPT="{helper_script}"',
                f'-DSEND_GATE_SCRIPT="{send_gate}"',
                f'-DCONFIRM_HELPER="{confirm}"',
                f'-DBRIDGE_ROOT="{root / "bridge"}"',
                f'-DPYTHON_INTERPRETER="{sys.executable}"',
                f'-DIMESSAGE_GATE_PATH="{self.gate}"',
                "-DGATE_SECRETS_VIA_FD=1",
                f"-DGATE_SECRETS_OWNER_UID={uid}",
                f"-DEXPECTED_USER_UID={user}",
                "-o", str(wrapper), str(REPO_ROOT / "bin" / "imessage_helper.c"),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return wrapper

    def run_wrapper(self, wrapper: Path, **kwargs) -> subprocess.CompletedProcess:
        return subprocess.run([str(wrapper)], capture_output=True, text=True, check=False, **kwargs)

    def test_secrets_arrive_on_a_pipe_after_the_privilege_drop(self) -> None:
        result = self.run_wrapper(self.build())
        self.assertEqual(result.returncode, 0, result.stderr)
        out = json.loads(result.stdout)
        self.assertTrue(out["is_pipe"])
        self.assertGreaterEqual(out["fd"], 3)
        self.assertEqual(json.loads(out["content"]), GATE)
        self.assertEqual((out["uid"], out["gid"]), (out["euid"], out["egid"]))
        self.assertEqual(out["gate_path"], str(self.gate))
        self.assertEqual(out["core_limit"], [0, 0])  # no core files, and it can't be raised back

    def test_closed_standard_fds_do_not_capture_the_secrets(self) -> None:
        wrapper = self.build()
        result = subprocess.run(
            ["/bin/sh", "-c", f'exec "{wrapper}" 0<&- '],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(json.loads(result.stdout)["fd"], 3)

    def test_group_or_world_readable_gate_json_is_refused(self) -> None:
        wrapper = self.build()
        self.gate.chmod(0o640)
        result = self.run_wrapper(wrapper)
        self.assertEqual(result.returncode, 5)
        self.assertIn("group/world permissions", result.stderr)
        self.assertNotIn(GATE["helper_token"], result.stdout + result.stderr)

    def test_symlinked_gate_json_is_refused(self) -> None:
        wrapper = self.build()
        real = self.root / "real.json"
        self.gate.rename(real)
        self.gate.symlink_to(real)
        result = self.run_wrapper(wrapper)
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot open gate config", result.stderr)

    def test_wrong_owner_is_refused(self) -> None:
        result = self.run_wrapper(self.build(owner_uid=0))
        self.assertEqual(result.returncode, 4)
        self.assertIn("expected 0", result.stderr)

    def test_oversized_gate_json_is_refused(self) -> None:
        wrapper = self.build()
        self.gate.write_text(json.dumps({**GATE, "pad": "x" * 9000}))
        self.assertEqual(self.run_wrapper(wrapper).returncode, 7)

    def test_other_users_are_refused(self) -> None:
        result = self.run_wrapper(self.build(expected_user=os.getuid() + 1))
        self.assertEqual(result.returncode, 12)
        self.assertIn("refusing uid", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_hardlinked_gate_json_is_refused(self) -> None:
        wrapper = self.build()
        os.link(self.gate, self.root / "extra-link.json")
        result = self.run_wrapper(wrapper)
        self.assertEqual(result.returncode, 3)
        self.assertIn("extra hard links", result.stderr)

    def test_missing_gate_json_is_refused(self) -> None:
        wrapper = self.build()
        self.gate.unlink()
        self.assertEqual(self.run_wrapper(wrapper).returncode, 2)


class ContactRefsFdTests(unittest.TestCase):
    def setUp(self) -> None:
        contact_refs._fd_config = None
        self.addCleanup(setattr, contact_refs, "_fd_config", None)

    def _pipe_with(self, payload: bytes) -> int:
        r, w = os.pipe()
        os.write(w, payload)
        os.close(w)
        return r

    def test_reads_once_closes_and_caches(self) -> None:
        fd = self._pipe_with(json.dumps(GATE).encode())
        with mock.patch.dict(os.environ, {"IMESSAGE_GATE_SECRETS_FD": str(fd)}):
            self.assertTrue(contact_refs.secrets_via_fd())
            self.assertEqual(contact_refs.load_gate_config(), GATE)
            with self.assertRaises(OSError):
                os.fstat(fd)  # closed after reading
            self.assertEqual(contact_refs.load_gate_config(), GATE)  # cached
            self.assertEqual(contact_refs._hmac_key(), GATE["contact_ref_hmac_key"].encode())

    def test_refuses_non_pipe_descriptor(self) -> None:
        with tempfile.TemporaryFile() as f:
            f.write(json.dumps(GATE).encode())
            f.flush()
            fd = os.dup(f.fileno())
        with mock.patch.dict(os.environ, {"IMESSAGE_GATE_SECRETS_FD": str(fd)}):
            with self.assertRaisesRegex(contact_refs.ContactRefError, "not a pipe"):
                contact_refs.load_gate_config()

    def test_refuses_bad_content_and_bad_fd(self) -> None:
        for payload in (b"{not json", b"[1, 2]", b"x" * (17 * 1024)):
            fd = self._pipe_with(payload[:60000])
            with self.subTest(payload=payload[:10]), mock.patch.dict(os.environ, {"IMESSAGE_GATE_SECRETS_FD": str(fd)}):
                contact_refs._fd_config = None
                with self.assertRaises(contact_refs.ContactRefError):
                    contact_refs.load_gate_config()
        with mock.patch.dict(os.environ, {"IMESSAGE_GATE_SECRETS_FD": "abc"}):
            with self.assertRaises(contact_refs.ContactRefError):
                contact_refs.load_gate_config()

    def test_bad_secrets_pipe_fails_closed_in_helper(self) -> None:
        fd = self._pipe_with(b"{not json")
        saved = helper._contact_refs._fd_config
        helper._contact_refs._fd_config = None
        self.addCleanup(setattr, helper._contact_refs, "_fd_config", saved)
        with mock.patch.dict(os.environ, {"IMESSAGE_GATE_SECRETS_FD": str(fd)}):
            ctx = helper._build_gate_context()
        self.assertTrue(ctx.enabled)
        self.assertIsNone(ctx.client)


class InstallerSetuidTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = (REPO_ROOT / "install-hardened.sh").read_text()

    def test_wrapper_is_setuid_and_reads_secrets_via_fd(self) -> None:
        self.assertIn("-DGATE_SECRETS_VIA_FD=1", self.script)
        self.assertIn(
            'sudo "$INSTALL_BIN" -o root -g wheel -m 4555 \\\n    "$BUILD_ROOT/grokbot-imessage-helper" "$WRAPPER_DEST"',
            self.script,
        )

    def test_wrapper_is_built_and_signed_as_root_in_a_root_only_dir(self) -> None:
        self.assertNotIn("mktemp", self.script)
        self.assertNotIn("BUILD_DIR", self.script)
        self.assertIn('sudo "$INSTALL_BIN" -d -o root -g wheel -m 700 "$BUILD_ROOT"', self.script)
        self.assertIn('sudo "$CLANG_BIN" -Wall -Wextra -Werror -O2', self.script)
        self.assertIn('"$CODE_ROOT/bin/imessage_helper.c"\n', self.script)
        self.assertIn('sudo "$CODESIGN_BIN" "${SIGN_ARGS[@]}" "$BUILD_ROOT/grokbot-imessage-helper"', self.script)
        for line in self.script.splitlines():
            stripped = line.strip()
            if stripped.startswith(("clang ", "codesign ")):
                self.fail(f"unprivileged build step: {stripped}")

    def test_wrapper_bakes_uid_and_real_python(self) -> None:
        self.assertIn('-DEXPECTED_USER_UID="$UID"', self.script)
        self.assertIn('-DPYTHON_INTERPRETER="\\"$REAL_PYTHON\\""', self.script)
        self.assertIn("os.path.realpath(sys.executable)", self.script)
        self.assertIn('hardened_python_is_trusted "$REAL_PYTHON"', self.script)

    def test_setuid_bit_cleared_before_replace_and_uninstall(self) -> None:
        chmod = self.script.index('sudo "$CHMOD_BIN" 0555 "$WRAPPER_DEST"')
        self.assertLess(chmod, self.script.index('-m 4555 \\\n    "$BUILD_ROOT/grokbot-imessage-helper"'))
        uninstall = (REPO_ROOT / "uninstall-hardened.sh").read_text()
        self.assertLess(uninstall.index('sudo "$CHMOD_BIN" 0555 "$wrapper"'), uninstall.index('sudo "$RM_BIN" -rf "$USER_ROOT"'))

    def test_legacy_acl_forces_secret_rotation(self) -> None:
        self.assertIn('grep -q "allow read"', self.script)
        self.assertIn("CONFIGURE_ARGS+=(--rotate-hmac-key)", self.script)
        self.assertIn("CONFIGURE_ARGS+=(--require-new-token)", self.script)
        self.assertIn("the old helper token was readable by your user", self.script)

    def test_gate_json_gets_no_user_acl(self) -> None:
        self.assertNotIn('allow read" "$GATE_JSON"', self.script)
        self.assertIn('sudo "$CHMOD_BIN" -N "$GATE_JSON"', self.script)
        # The allowlist keeps its user read ACL (legacy mode reads it as the user).
        self.assertIn('allow read" "$ALLOWLIST"', self.script)


class ConfigureGateRotationTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("configure_gate_rot", REPO_ROOT / "tools" / "configure_gate.py")
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        self._tmp = tempfile.TemporaryDirectory(prefix="gate-rotate-")
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "gate.json"
        self.path.write_text(json.dumps(GATE))

    def run_tool(self, argv, stdin=""):
        import io
        from contextlib import redirect_stderr

        with mock.patch.object(sys, "stdin", io.StringIO(stdin)), redirect_stderr(io.StringIO()):
            return self.tool.main(["--gate-json", str(self.path), *argv])

    def test_rotates_hmac_key_and_keeps_token(self) -> None:
        self.run_tool(["--rotate-hmac-key"])
        data = json.loads(self.path.read_text())
        self.assertNotEqual(data["contact_ref_hmac_key"], GATE["contact_ref_hmac_key"])
        self.assertEqual(data["helper_token"], GATE["helper_token"])

    def test_require_new_token_refuses_the_old_one(self) -> None:
        with self.assertRaises(SystemExit):
            self.run_tool(
                ["--gate-url", "https://g.test", "--token-stdin", "--require-new-token", "--rotate-hmac-key"],
                stdin=GATE["helper_token"],
            )
        self.assertEqual(json.loads(self.path.read_text()), GATE)
        new = "n" * 43
        self.run_tool(
            ["--gate-url", "https://g.test", "--token-stdin", "--require-new-token", "--rotate-hmac-key"], stdin=new
        )
        self.assertEqual(json.loads(self.path.read_text())["helper_token"], new)


@unittest.skipUnless(sys.platform == "darwin", "macOS codesign/DevToolsSecurity")
class DoctorAttachCheckTests(unittest.TestCase):
    def test_python_attach_checks_report(self) -> None:
        spec = importlib.util.spec_from_file_location("doctor_attach", REPO_ROOT / "tools" / "doctor.py")
        doctor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(doctor)
        checks = doctor.python_attach_checks(skip_codesign=False)
        self.assertIn(checks["python_not_debuggable"]["status"], ("pass", "fail"))
        self.assertIn(checks["developer_mode_off"]["status"], ("pass", "warn"))
