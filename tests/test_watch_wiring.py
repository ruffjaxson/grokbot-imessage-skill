"""watch_tick.sh (LaunchAgent trigger) and configure_watch_webhook.sh."""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tests._helper_loader import REPO_ROOT

WATCH_TICK = REPO_ROOT / "tools" / "watch_tick.sh"
CONFIGURE = REPO_ROOT / "tools" / "configure_watch_webhook.sh"
KEY = "whk_" + "A1b2C3d4" * 4
URL = "https://api.example.test/automations/webhook/auto_123"


@unittest.skipUnless(shutil.which("plutil"), "macOS plutil required")
class WatchTickTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="grokbot-watch-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bridge = self.root / "bridge"
        for d in ("control/requests", "control/responses", "watch"):
            (self.bridge / d).mkdir(parents=True)
        self.curl_log = self.root / "curl.log"
        self.curl_exit = 0
        self.fake_curl = self.root / "curl"
        self.fake_curl.write_text(
            "#!/bin/bash\n"
            f'printf "ARGV %s\\n" "$*" >> "{self.curl_log}"\n'
            f'while IFS= read -r line; do printf "STDIN %s\\n" "$line" >> "{self.curl_log}"; done\n'
            f'exit "$(cat "{self.root}/curl_exit" 2>/dev/null || echo 0)"\n'
        )
        self.fake_curl.chmod(0o755)
        self.configure(min_interval=120)

    def configure(self, min_interval: int) -> None:
        (self.bridge / "watch" / "webhook.json").write_text(
            json.dumps({"url": URL, "key": KEY, "min_interval_seconds": min_interval})
        )

    def tick(self, response: dict | None, timeout: int = 5) -> subprocess.CompletedProcess:
        """Run watch_tick.sh while a fake helper answers its request."""
        stop = threading.Event()

        def responder():
            requests = self.bridge / "control" / "requests"
            while not stop.is_set():
                for req in requests.glob("request-*.json"):
                    body = json.loads(req.read_text())
                    self.last_request = body
                    req.unlink()
                    if response is not None:
                        out = {"id": body["id"], "action": "watch_tick", **response}
                        (self.bridge / "control" / "responses" / f"response-{body['id']}.json").write_text(
                            json.dumps(out)
                        )
                time.sleep(0.05)

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            return subprocess.run(
                ["/bin/bash", str(WATCH_TICK), str(self.bridge)],
                env={"WATCH_TICK_CURL": str(self.fake_curl), "WATCH_TICK_TIMEOUT_S": str(timeout), "PATH": "/usr/bin:/bin"},
                capture_output=True, text=True, timeout=30, check=False,
            )
        finally:
            stop.set()
            thread.join()

    def posts(self) -> list[str]:
        if not self.curl_log.exists():
            return []
        return [line for line in self.curl_log.read_text().splitlines() if line.startswith("ARGV")]

    def state(self) -> tuple[int, int]:
        last, pending = (self.bridge / "watch" / "trigger.state").read_text().split()
        return int(last), int(pending)

    def test_no_webhook_means_no_request_at_all(self) -> None:
        (self.bridge / "watch" / "webhook.json").unlink()
        result = subprocess.run(["/bin/bash", str(WATCH_TICK), str(self.bridge)], capture_output=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(list((self.bridge / "control" / "requests").iterdir()), [])

    def test_new_messages_trigger_a_content_free_post(self) -> None:
        result = self.tick({"ok": True, "new_count": 3})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.last_request["action"], "watch_tick")
        [argv] = self.posts()
        self.assertNotIn(KEY, argv)  # the key never appears on a command line
        self.assertIn('{"event":"imessage_watch"}', argv)
        self.assertIn("--proto =https", argv)
        self.assertTrue(argv.startswith("ARGV -q "))  # ~/.curlrc is ignored
        log = self.curl_log.read_text()
        self.assertIn(f'STDIN header = "Authorization: Bearer {KEY}"', log)
        self.assertIn(f'STDIN url = "{URL}"', log)
        self.assertNotIn("3", argv.split("--data", 1)[1])  # no count leaves the Mac
        self.assertEqual(self.state()[1], 0)

    def test_zero_new_messages_do_not_trigger(self) -> None:
        self.tick({"ok": True, "new_count": 0})
        self.assertEqual(self.posts(), [])

    def test_debounce_then_deliver_pending(self) -> None:
        self.tick({"ok": True, "new_count": 1})
        self.tick({"ok": True, "new_count": 2})
        self.assertEqual(len(self.posts()), 1)
        last, pending = self.state()
        self.assertEqual(pending, 1)
        (self.bridge / "watch" / "trigger.state").write_text(f"{last - 200} 1\n")
        self.tick({"ok": True, "new_count": 0})  # pending trigger goes out once the interval passes
        self.assertEqual(len(self.posts()), 2)
        self.assertEqual(self.state()[1], 0)

    def test_helper_error_or_timeout_never_triggers(self) -> None:
        self.tick({"ok": False, "error": "approval gate unavailable"})
        self.tick(None, timeout=1)
        self.assertEqual(self.posts(), [])
        self.assertEqual(list((self.bridge / "control" / "requests").iterdir()), [])

    def test_failed_post_stays_pending(self) -> None:
        (self.root / "curl_exit").write_text("22")
        self.tick({"ok": True, "new_count": 1})
        self.assertEqual(self.state()[1], 1)
        self.assertIn("webhook POST failed", (self.bridge / "watch" / "log.txt").read_text())

    def test_invalid_config_is_ignored(self) -> None:
        (self.bridge / "watch" / "webhook.json").write_text(json.dumps({"url": "http://x.test/", "key": KEY}))
        self.tick({"ok": True, "new_count": 1})
        self.assertEqual(self.posts(), [])


@unittest.skipUnless(shutil.which("plutil"), "macOS plutil required")
class ConfigureWebhookTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="grokbot-webhook-cfg-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bridge = self.root / "bridge"
        self.bridge.mkdir()
        self.key_file = self.root / "key"
        self.key_file.write_text(KEY + "\n")

    def run_tool(self, *args, curl: str = "/usr/bin/false") -> subprocess.CompletedProcess:
        return subprocess.run(
            ["/bin/bash", str(CONFIGURE), *args],
            env={"GROKBOT_IMESSAGE_BRIDGE": str(self.bridge), "WATCH_TICK_CURL": curl, "PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False,
        )

    def test_saves_private_config_without_echoing_key(self) -> None:
        result = self.run_tool("--url", URL, "--key-file", str(self.key_file))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(KEY, result.stdout + result.stderr)
        config = self.bridge / "watch" / "webhook.json"
        self.assertEqual(json.loads(config.read_text()), {"url": URL, "key": KEY, "min_interval_seconds": 120})
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.bridge / "watch").stat().st_mode), 0o700)

    def test_rejects_bad_input(self) -> None:
        for args in (
            ("--url", "http://api.example.test/hook", "--key-file", str(self.key_file)),
            ("--url", URL, "--key-file", str(self.key_file), "--min-interval", "5"),
            ("--url", URL),  # no key and not interactive
        ):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_tool(*args).returncode, 0)
        self.key_file.write_text("short\n")
        self.assertNotEqual(self.run_tool("--url", URL, "--key-file", str(self.key_file)).returncode, 0)
        self.assertFalse((self.bridge / "watch" / "webhook.json").exists())

    def test_test_and_disable(self) -> None:
        self.run_tool("--url", URL, "--key-file", str(self.key_file))
        self.assertEqual(self.run_tool("--test", curl="/usr/bin/true").returncode, 0)
        self.assertNotEqual(self.run_tool("--test", curl="/usr/bin/false").returncode, 0)
        self.assertEqual(self.run_tool("--disable").returncode, 0)
        self.assertFalse((self.bridge / "watch" / "webhook.json").exists())


class WatchInstallTests(unittest.TestCase):
    def test_installer_installs_and_loads_watch_agent(self) -> None:
        script = (REPO_ROOT / "install-hardened.sh").read_text()
        self.assertIn('"$SOURCE_ROOT/tools/watch_tick.sh" "$CODE_ROOT/tools/watch_tick.sh"', script)
        self.assertIn('render_plist "$WATCH_PLIST_DEST" "$WATCH_PLIST_TEMPLATE"', script)
        self.assertIn('launchctl bootstrap "gui/$UID" "$WATCH_PLIST_DEST"', script)
        uninstall = (REPO_ROOT / "uninstall-hardened.sh").read_text()
        self.assertIn('for label in "$LABEL" "$LABEL-watch"; do', uninstall)

    def test_watch_plist_runs_every_minute_without_fda_binary(self) -> None:
        text = (REPO_ROOT / "com.jeffhuber.grokbot-imessage-watch.plist.template").read_text()
        self.assertIn("<integer>60</integer>", text)
        self.assertIn("{{CODE_ROOT}}/tools/watch_tick.sh", text)
        self.assertNotIn("grokbot-imessage-helper</string>", text)
        if shutil.which("plutil"):
            result = subprocess.run(
                ["plutil", "-lint", str(REPO_ROOT / "com.jeffhuber.grokbot-imessage-watch.plist.template")],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
