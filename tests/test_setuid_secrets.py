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
import json, os, stat, sys
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

    def build(self, owner_uid: int | None = None) -> Path:
        root = self.root
        helper_script = root / "helper.py"
        helper_script.write_text(PROBE)
        send_gate = root / "send_gate.py"
        send_gate.write_text("# fixture\n")
        confirm = root / "confirm"
        confirm.write_text("#!/bin/sh\nexit 0\n")
        for path, mode in ((helper_script, 0o500), (send_gate, 0o500), (confirm, 0o700)):
            path.chmod(mode)
        wrapper = root / f"wrapper-{owner_uid}"
        uid = os.getuid() if owner_uid is None else owner_uid
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
            'sudo "$INSTALL_BIN" -o root -g wheel -m 4555 \\\n    "$BUILD_DIR/grokbot-imessage-helper"',
            self.script,
        )

    def test_gate_json_gets_no_user_acl(self) -> None:
        self.assertNotIn('allow read" "$GATE_JSON"', self.script)
        self.assertIn('sudo "$CHMOD_BIN" -N "$GATE_JSON"', self.script)
        # The allowlist keeps its user read ACL (legacy mode reads it as the user).
        self.assertIn('allow read" "$ALLOWLIST"', self.script)
