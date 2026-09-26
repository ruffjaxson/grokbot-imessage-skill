from __future__ import annotations

import importlib.util
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests._helper_loader import REPO_ROOT, helper

CONTACT_REFS_PATH = REPO_ROOT / "bin" / "contact_refs.py"
_spec = importlib.util.spec_from_file_location("contact_refs", CONTACT_REFS_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"could not load {CONTACT_REFS_PATH}")
contact_refs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(contact_refs)

TEST_KEY = b"test-hmac-key"


def _match(name: str, handle: str) -> dict[str, str]:
    return contact_refs.lookup_match(handle, name, key=TEST_KEY)


class ContactRefMaskingTests(unittest.TestCase):
    def test_mask_phone_and_email(self) -> None:
        self.assertEqual(contact_refs.mask_handle("4155551234"), "***-***-1234")
        self.assertEqual(
            contact_refs.mask_handle("emma@example.com"), "e***@example.com"
        )

    def test_contacts_lookup_never_returns_raw_handles(self) -> None:
        contacts = {
            "4155551234": "Emma Ruff",
            "emma@example.com": "Emma Ruff",
        }
        helper._CONTACT_RAW_HANDLES.update(
            {
                "4155551234": "+14155551234",
                "emma@example.com": "emma@example.com",
            }
        )
        result = helper.action_contacts_lookup(
            {"name": "Emma"}, None, contacts, helper.PrivacyPolicy(mode="blocklist", blocklist=(), allowlist=())
        )
        blob = json.dumps(result)
        self.assertNotIn("+14155551234", blob)
        self.assertNotIn("emma@example.com", blob)
        self.assertNotIn("phone_last10", blob)
        self.assertIn("e***@example.com", blob)
        self.assertEqual(result["match_count"], 2)
        for match in result["matches"]:
            self.assertIn("masked_handle", match)
            self.assertIn("contact_ref", match)
            self.assertIn("service", match)
            self.assertRegex(match["contact_ref"], r"^[0-9a-f]{64}$")

    def test_unknown_contact_ref_rejected(self) -> None:
        contacts = {"4155551234": "Emma Ruff"}
        with self.assertRaisesRegex(ValueError, "unknown contact_ref"):
            helper.resolve_send_recipient(
                {"contact_ref": "0" * 64}, contacts
            )


class ContactRefRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="grokbot-contact-ref-test-")
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        gate = root / "gate.json"
        gate.write_text(
            json.dumps({"schema_version": 1, "contact_ref_hmac_key": "test-hmac-key"}),
            encoding="utf-8",
        )
        bridge = root / "bridge"
        (bridge / "control" / "requests").mkdir(parents=True)
        (bridge / "control" / "responses").mkdir(parents=True)
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "IMESSAGE_GATE_PATH": str(gate),
                "IMESSAGE_BRIDGE_DIR": str(bridge),
            },
        )
        self._env_patch.start()
        self.addCleanup(self._env_patch.stop)

    def test_ref_round_trip_and_send_preview(self) -> None:
        contacts = {"4155551234": "Emma Ruff"}
        helper._CONTACT_RAW_HANDLES["4155551234"] = "+14155551234"
        match = _match("Emma Ruff", "4155551234")
        normalized = contact_refs.resolve_contact_ref(match["contact_ref"], contacts, key=TEST_KEY)
        self.assertEqual(normalized, "4155551234")
        self.assertEqual(helper.contact_raw_handle(normalized), "+14155551234")

        with mock.patch.object(helper, "mint_send_nonce", return_value="nonce-1"):
            preview = helper.action_send_preview(
                {"contact_ref": match["contact_ref"], "text": "hello"},
                None,
                contacts,
                helper.PrivacyPolicy(mode="blocklist", blocklist=(), allowlist=()),
            )
        self.assertEqual(preview["preview"]["masked_handle"], "***-***-1234")
        self.assertEqual(preview["preview"]["contact_ref"], match["contact_ref"])
        self.assertNotIn("to", preview["preview"])
        self.assertNotIn("+14155551234", json.dumps(preview))

        with mock.patch.object(helper, "_run_send_confirmation", return_value=True), mock.patch.object(
            helper, "_run_osascript", return_value=(0, "", "")
        ), mock.patch.object(helper, "consume_send_nonce"):
            sent = helper.action_send(
                {
                    "contact_ref": match["contact_ref"],
                    "text": "hello",
                    "send_nonce": "nonce-1",
                },
                None,
                contacts,
                helper.PrivacyPolicy(mode="blocklist", blocklist=(), allowlist=()),
            )
        self.assertEqual(sent["sent"]["contact_ref"], match["contact_ref"])
        self.assertNotIn("to", sent["sent"])
