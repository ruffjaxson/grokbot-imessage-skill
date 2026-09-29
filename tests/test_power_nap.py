"""power_nap_tick.sh and hardened install wiring for sleep wakes."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests._helper_loader import REPO_ROOT

POWER_NAP = REPO_ROOT / "tools" / "power_nap_tick.sh"
PLIST = REPO_ROOT / "com.jeffhuber.grokbot-imessage-power-nap.plist.template"


@unittest.skipUnless(shutil.which("plutil"), "macOS plutil required")
class PowerNapTickTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="grokbot-power-nap-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.log = self.root / "power-nap.log"
        self.pmset_log = self.root / "pmset.log"
        self.fake_pmset = self.root / "pmset"
        self.fake_pmset.write_text(
            "#!/bin/bash\n"
            f'printf "%s\\n" "$*" >> "{self.pmset_log}"\n'
            'if [[ "$1" == "-g" && "$2" == "ps" ]]; then\n'
            '  if test -f "' + str(self.root / "on_ac") + '"; then\n'
            '    echo "Now drawing from \'AC Power\'"\n'
            "  else\n"
            '    echo "Now drawing from \'Battery Power\'"\n'
            "  fi\n"
            '  exit 0\n'
            'fi\n'
            'if [[ "$1" == "-g" && "$2" == "sched" ]]; then\n'
            '  echo "Scheduled power events:"\n'
            '  exit 0\n'
            'fi\n'
            'if [[ "$1" == "schedule" ]]; then\n'
            '  exit 0\n'
            'fi\n'
            "exit 0\n"
        )
        self.fake_pmset.chmod(0o755)
        self.bridge = self.root / "bridge"
        (self.bridge / "watch").mkdir(parents=True)
        self.code = self.root / "code"
        (self.code / "tools").mkdir(parents=True)
        shutil.copy2(REPO_ROOT / "tools" / "watch_tick.sh", self.code / "tools" / "watch_tick.sh")
        self.env = {
            "PATH": "/usr/bin:/bin",
            "POWER_NAP_OWNER": "com.jeffhuber.grokbot-imessage-power-nap.test",
            "POWER_NAP_INTERVAL_S": "420",
            "POWER_NAP_AWAKE_SKIP_S": "180",
            "POWER_NAP_MIN_TICK_GAP_S": "90",
            "POWER_NAP_TARGET_USER": os.environ.get("USER", "tester"),
            "POWER_NAP_TARGET_UID": str(os.getuid()),
            "POWER_NAP_TARGET_HOME": str(Path.home()),
            "POWER_NAP_CODE_ROOT": str(self.code),
            "POWER_NAP_BRIDGE_ROOT": str(self.bridge),
            "POWER_NAP_STATE_DIR": str(self.state),
            "POWER_NAP_LOG": str(self.log),
            "POWER_NAP_PMSET": str(self.fake_pmset),
            "POWER_NAP_SYSCTL": "/usr/sbin/sysctl",
        }
        (self.root / "on_ac").write_text("")

    def run_tick(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", str(POWER_NAP)],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_on_battery_cancels_and_schedules_nothing(self) -> None:
        (self.root / "on_ac").unlink()
        result = self.run_tick()
        self.assertEqual(result.returncode, 0, result.stderr)
        joined = self.pmset_log.read_text()
        self.assertNotIn("schedule wake", joined)
        self.assertIn("on battery", self.log.read_text())

    def test_on_ac_schedules_relative_wake(self) -> None:
        result = self.run_tick()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("schedule wake", self.pmset_log.read_text())
        self.assertTrue((self.state / "next_wake.epoch").is_file())

    def test_long_uptime_skips_watch_tick(self) -> None:
        self.env["POWER_NAP_SYSCTL"] = str(self.root / "sysctl")
        (self.root / "sysctl").write_text(
            "#!/bin/bash\n"
            'if [[ "$1" == "-n" ]]; then\n'
            f'  echo "{{ sec = $(( $(date +%s) - 600 )), usec = 0 }}"\n'
            "else\n"
            "  exec /usr/sbin/sysctl \"$@\"\n"
            "fi\n"
        )
        (self.root / "sysctl").chmod(0o755)
        result = self.run_tick()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("user LaunchAgent", self.log.read_text())
        self.assertNotIn("running watch_tick", self.log.read_text())


class PowerNapInstallTests(unittest.TestCase):
    def test_installer_wires_daemon_and_uninstall_cleans_up(self) -> None:
        install = (REPO_ROOT / "install-hardened.sh").read_text()
        self.assertIn('"$SOURCE_ROOT/tools/power_nap_tick.sh" "$CODE_ROOT/tools/power_nap_tick.sh"', install)
        self.assertIn('sudo launchctl bootstrap system "$POWER_NAP_PLIST_DEST"', install)
        self.assertIn("render_power_nap_plist", install)
        uninstall = (REPO_ROOT / "uninstall-hardened.sh").read_text()
        self.assertIn("POWER_NAP_LABEL", uninstall)
        self.assertIn('"$PMSET_BIN" schedule cancel wake', uninstall)

    def test_plist_template_has_interval_and_script(self) -> None:
        text = PLIST.read_text()
        self.assertIn("<integer>420</integer>", text)
        self.assertIn("POWER_NAP_INTERVAL_S", text)
        self.assertIn("power_nap_tick.sh", text)
        if shutil.which("plutil"):
            result = subprocess.run(
                ["plutil", "-lint", str(PLIST)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_doctor_mentions_power_nap(self) -> None:
        source = (REPO_ROOT / "tools" / "doctor.py").read_text()
        self.assertIn("power_nap_launchd", source)
        self.assertIn("power_nap_wake_schedule", source)

