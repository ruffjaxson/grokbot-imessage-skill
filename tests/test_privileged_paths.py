from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

from tests._helper_loader import REPO_ROOT


class PrivilegedPathTests(unittest.TestCase):
    def test_check_privileged_paths_passes(self) -> None:
        result = subprocess.run(
            ["python3", str(REPO_ROOT / "tools" / "check_privileged_paths.py")],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=result.stdout + result.stderr,
        )

    def test_privileged_tools_resolve_chown_on_macos(self) -> None:
        if os.uname().sysname != "Darwin":
            self.skipTest("macOS-only path resolution")
        script = REPO_ROOT / "tools" / "privileged_tools.sh"
        result = subprocess.run(
            [
                "bash",
                "-lc",
                (
                    "PATH=/usr/bin:/bin:/usr/sbin:/sbin; "
                    f"source '{script}'; "
                    "load_privileged_tool_paths; "
                    "printf '%s\\n' \"$CHOWN_BIN\""
                ),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        chown_path = result.stdout.strip()
        self.assertTrue(chown_path.endswith("/chown"))
        self.assertTrue(Path(chown_path).is_file())
        self.assertNotEqual(chown_path, "/usr/bin/chown")

    def test_install_hardened_sources_privileged_tools(self) -> None:
        text = (REPO_ROOT / "install-hardened.sh").read_text(encoding="utf-8")
        self.assertIn("privileged_tools.sh", text)
        self.assertIn("load_privileged_tool_paths", text)
        self.assertNotIn("/usr/bin/chown", text)


if __name__ == "__main__":
    unittest.main()
