from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
HELPER_PATH = REPO_ROOT / "bin" / "helper.py"

_test_bridge = tempfile.mkdtemp(prefix="grokbot-test-gate-")
_test_gate = pathlib.Path(_test_bridge) / "contacts" / "gate.json"
_test_gate.parent.mkdir(parents=True, exist_ok=True)
_test_gate.write_text(
    json.dumps({"schema_version": 1, "contact_ref_hmac_key": "test-hmac-key"}),
    encoding="utf-8",
)
os.environ.setdefault("IMESSAGE_BRIDGE_DIR", _test_bridge)
os.environ.setdefault("IMESSAGE_GATE_PATH", str(_test_gate))

spec = importlib.util.spec_from_file_location("grokbot_imessage_helper", HELPER_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"could not load helper from {HELPER_PATH}")

helper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = helper
spec.loader.exec_module(helper)
