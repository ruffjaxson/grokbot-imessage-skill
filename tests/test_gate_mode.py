"""Approval-gate mode (protocol 1.3).

A FakeGate stands in for the gate service at the client boundary and raises
the real gate_client exceptions, so the helper's fail-closed handling is
exercised as written. GateClient itself is tested separately against a fake
opener and a real local HTTPS server.
"""
from __future__ import annotations

import http.server
import importlib.util
import io
import json
import os
import shutil
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tests._helper_loader import REPO_ROOT, helper
from tests.test_list_chats import TEXT_SENTINEL, build_fixture_db


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate_client = _load("gate_client_under_test", REPO_ROOT / "bin" / "gate_client.py")
configure_gate = _load("configure_gate_under_test", REPO_ROOT / "tools" / "configure_gate.py")

TOKEN = "helper-token-" + "x" * 32
ALICE = "+14155551234"
CAROL = "+14155559876"
BOB = "bob@example.com"
CONTACTS = {"4155551234": "Alice Example", "4155559876": "Carol Example", BOB: "Bob Example"}


def grant(gid: int, handle: str, scope: str, expires_at: str | None = None) -> dict:
    return {
        "id": gid,
        "handle": handle,
        "display_name": "x",
        "scope": scope,
        "expires_at": expires_at,
        "revoked_at": None,
        "approval_id": None,
        "created_at": "2026-09-25T00:00:00+00:00",
    }


class FakeGate:
    def __init__(self, grants=None):
        self.grants = list(grants or [])
        self.approvals: dict[str, dict] = {}
        self.audits: list[tuple[str, dict]] = []
        self.revoked: list[int] = []
        self.calls: list[str] = []
        self.fail: Exception | None = None
        self.config = gate_client.GateConfig("https://gate.test", TOKEN)

    def _enter(self, name):
        self.calls.append(name)
        if self.fail is not None:
            raise self.fail

    def policy(self):
        self._enter("policy")
        return {"generated_at": "2026-09-25T00:00:00+00:00", "grants": list(self.grants)}

    def create_approval(self, kind, payload):
        self._enter("create_approval")
        aid = str(uuid.uuid4())
        self.approvals[aid] = {"kind": kind, "payload": payload, "status": "pending"}
        return {
            "id": aid,
            "kind": kind,
            "status": "pending",
            "approve_url": f"https://gate.test/a/{aid}",
            "expires_at": "2026-09-25T00:10:00+00:00",
            "payload_sha256": gate_client.payload_sha256(payload),
        }

    def get_approval(self, aid):
        self._enter("get_approval")
        a = self.approvals.get(aid)
        if a is None:
            raise gate_client.GateError(404, "approval not found")
        out = {"id": aid, "kind": a["kind"], "status": a["status"], "expires_at": "x", "decided_at": None}
        if a.get("grants"):
            out["grants"] = a["grants"]
        return out

    def consume(self, aid):
        self._enter("consume")
        a = self.approvals.get(aid)
        if a is None:
            raise gate_client.GateError(404, "approval not found")
        if a["status"] != "approved":
            raise gate_client.GateError(409, {"error": "not_consumable", "status": a["status"]})
        a["status"] = "consumed"
        return {
            "id": aid,
            "kind": "send",
            "status": "consumed",
            "payload": a["payload"],
            "payload_sha256": gate_client.payload_sha256(a["payload"]),
        }

    def revoke_grant(self, gid):
        self._enter("revoke_grant")
        self.revoked.append(gid)
        scope = next((g["scope"] for g in self.grants if g["id"] == gid), None)
        return {"grant": {"id": gid, "scope": scope}, "revoked": True}

    def audit(self, event, **kwargs):
        self._enter("audit")
        self.audits.append((event, kwargs))

    def approve(self, aid, payload_override=None):
        self.approvals[aid]["status"] = "approved"
        if payload_override is not None:
            self.approvals[aid]["payload"] = payload_override


class GateModeTestCase(unittest.TestCase):
    """Installs a FakeGate as the helper's gate context and isolates state."""

    grants: list = []

    def setUp(self) -> None:
        self.gate = FakeGate(self.grants)
        self._saved_ctx = helper._GATE_CONTEXT
        helper._GATE_CONTEXT = helper.GateContext(client=self.gate, module=gate_client)
        self.addCleanup(setattr, helper, "_GATE_CONTEXT", self._saved_ctx)

        # A symlink-free private bridge (macOS /var is a symlink).
        bridge = Path(os.path.realpath(tempfile.mkdtemp(prefix="gate-bridge-")))
        bridge.chmod(0o700)
        self.addCleanup(shutil.rmtree, bridge, True)
        self.bridge = bridge
        for name, value in (
            ("BRIDGE_ROOT", bridge),
            ("REQUESTS_DIR", bridge / "control" / "requests"),
            ("RESPONSES_DIR", bridge / "control" / "responses"),
            ("LOG_PATH", bridge / "control" / "log.txt"),
            ("WATCH_STATE_PATH", bridge / "state" / "watch.json"),
        ):
            patcher = mock.patch.object(helper, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.blocklist = Path(tempfile.mkdtemp(prefix="gate-blocklist-")) / "blocked.txt"
        self.addCleanup(shutil.rmtree, self.blocklist.parent, True)
        patcher = mock.patch.object(helper, "BLOCKLIST_PATH", self.blocklist)
        patcher.start()
        self.addCleanup(patcher.stop)

        saved_raw = dict(helper._CONTACT_RAW_HANDLES)
        saved_labels = dict(helper._CONTACT_HANDLE_LABELS)
        helper._CONTACT_RAW_HANDLES.update(
            {"4155551234": "(415) 555-1234", "4155559876": "+1 415-555-9876", BOB: BOB}
        )
        helper._CONTACT_HANDLE_LABELS.update({"4155551234": "mobile", "4155559876": "home", BOB: "email 1"})
        self.addCleanup(self._restore_contacts, saved_raw, saved_labels)

        self.scripts: list[str] = []
        patcher = mock.patch.object(helper, "_run_osascript", side_effect=self._fake_osascript)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def _restore_contacts(raw, labels):
        helper._CONTACT_RAW_HANDLES.clear()
        helper._CONTACT_RAW_HANDLES.update(raw)
        helper._CONTACT_HANDLE_LABELS.clear()
        helper._CONTACT_HANDLE_LABELS.update(labels)

    def _fake_osascript(self, script, timeout=None):
        self.scripts.append(script)
        return 0, "", ""

    def policy(self):
        return helper.load_gate_policy(helper._GATE_CONTEXT)

    def ref(self, key: str) -> str:
        return helper._contact_refs.make_contact_ref(key)

    def run_action(self, name, params, conn=None, contacts=None):
        return helper.ACTIONS[name](params, conn, CONTACTS if contacts is None else contacts, self.policy())


# ---------------------------------------------------------------------------
# Payload hashing must match the gate byte-for-byte
# ---------------------------------------------------------------------------
class PayloadHashTests(unittest.TestCase):
    # Vectors produced by imessage_gate.models.payload_sha256 on the gate side.
    VECTORS = [
        (
            {
                "handle": "+14155551234",
                "display_name": "Emma Ruff",
                "service": "iMessage",
                "text": 'Running late \u2014 10 min \U0001f64f\nsee you "soon"',
            },
            "d9e84882605061ed98199fcb7358d7f8dab87da85966345a4d8d5bcc84b9e4bf",
        ),
        (
            {"handle": "emma@example.com", "display_name": "Emma Ruff", "scopes": ["read", "watch"], "duration_seconds": None},
            "c73d084c696f895bbee92863685bde0507d5188690961544e2961cde1b17e82d",
        ),
        (
            {"handle": "+14155551234", "display_name": "Emma", "scopes": ["send"], "duration_seconds": 604800},
            "609277eb4623ee26148de6ec4be6a12b3434c0262108a29c916cedd88bd8e4f3",
        ),
    ]

    def test_matches_gate_vectors(self) -> None:
        for payload, expected in self.VECTORS:
            with self.subTest(payload=payload):
                self.assertEqual(gate_client.payload_sha256(payload), expected)

    def test_key_order_is_irrelevant(self) -> None:
        payload, expected = self.VECTORS[0]
        reordered = dict(reversed(list(payload.items())))
        self.assertEqual(gate_client.payload_sha256(reordered), expected)


# ---------------------------------------------------------------------------
# gate_client: config and transport
# ---------------------------------------------------------------------------
class GateConfigTests(unittest.TestCase):
    def test_gate_url_validation(self) -> None:
        self.assertEqual(
            gate_client.validate_gate_url("https://imessage-gate.example-tailnet.ts.net/"),
            "https://imessage-gate.example-tailnet.ts.net",
        )
        self.assertEqual(gate_client.validate_gate_url("https://localhost:8443"), "https://localhost:8443")
        for bad in (
            "http://gate.test",
            "https://gate.test/v1",
            "https://user:pw@gate.test",
            "https://gate.test?x=1",
            "gate.test",
            "",
            None,
        ):
            with self.subTest(bad=bad), self.assertRaises(gate_client.GateConfigError):
                gate_client.validate_gate_url(bad)

    def test_config_from_gate_json(self) -> None:
        self.assertIsNone(gate_client.config_from_gate_json({"contact_ref_hmac_key": "k"}))
        cfg = gate_client.config_from_gate_json({"gate_url": "https://gate.test", "helper_token": TOKEN})
        self.assertEqual(cfg.url, "https://gate.test")
        self.assertNotIn(TOKEN, repr(cfg))
        for partial in ({"gate_url": "https://gate.test"}, {"helper_token": TOKEN}):
            with self.subTest(partial=partial), self.assertRaises(gate_client.GateConfigError):
                gate_client.config_from_gate_json(partial)
        with self.assertRaises(gate_client.GateConfigError):
            gate_client.config_from_gate_json({"gate_url": "https://gate.test", "helper_token": "short"})


class _FakeResponse(io.BytesIO):
    def __init__(self, status, body, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, req, timeout=None):
        self.requests.append(req)
        status, body = self.responses.pop(0)
        raw = json.dumps(body).encode() if not isinstance(body, bytes) else body
        if status >= 400:
            import urllib.error

            raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(raw))
        resp = _FakeResponse(status, raw)
        resp.headers = mock.MagicMock()
        resp.headers.items.return_value = []
        return resp


class GateClientTests(unittest.TestCase):
    def client(self, *responses):
        opener = FakeOpener(responses)
        return gate_client.GateClient(gate_client.GateConfig("https://gate.test", TOKEN), opener=opener), opener

    def test_policy_sends_bearer_token_to_pinned_origin(self) -> None:
        client, opener = self.client((200, {"grants": []}))
        self.assertEqual(client.policy(), {"grants": []})
        req = opener.requests[0]
        self.assertEqual(req.full_url, "https://gate.test/v1/policy")
        self.assertEqual(req.get_header("Authorization"), f"Bearer {TOKEN}")

    def test_malformed_policy_is_unavailable(self) -> None:
        client, _ = self.client((200, {"nope": 1}))
        with self.assertRaises(gate_client.GateUnavailable):
            client.policy()

    def test_auth_and_server_errors_are_unavailable(self) -> None:
        for status in (401, 403, 500, 503):
            client, _ = self.client((status, {"detail": "x"}))
            with self.subTest(status=status), self.assertRaises(gate_client.GateUnavailable):
                client.policy()

    def test_conflict_carries_approval_status(self) -> None:
        aid = str(uuid.uuid4())
        client, _ = self.client((409, {"detail": {"error": "not_consumable", "status": "pending"}}))
        with self.assertRaises(gate_client.GateError) as caught:
            client.consume(aid)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(caught.exception.detail_status, "pending")

    def test_consume_rejects_payload_hash_mismatch(self) -> None:
        aid = str(uuid.uuid4())
        payload = {"handle": ALICE, "display_name": "A", "service": "iMessage", "text": "hi"}
        client, _ = self.client(
            (200, {"id": aid, "kind": "send", "payload": payload, "payload_sha256": "0" * 64})
        )
        with self.assertRaisesRegex(gate_client.GateUnavailable, "hash mismatch"):
            client.consume(aid)

    def test_create_approval_rejects_normalization_drift(self) -> None:
        payload = {"handle": ALICE, "display_name": "A", "service": "iMessage", "text": "hi"}
        client, _ = self.client((201, {"id": "x", "payload_sha256": "f" * 64}))
        with self.assertRaisesRegex(gate_client.GateUnavailable, "different payload"):
            client.create_approval("send", payload)

    def test_approval_id_must_be_uuid(self) -> None:
        client, opener = self.client()
        for bad in ("../policy", "x", "", None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                client.consume(bad)
        self.assertEqual(opener.requests, [])


def _make_cert(directory: Path) -> tuple[Path, Path] | None:
    openssl = shutil.which("openssl")
    if not openssl:
        return None
    cert, key = directory / "cert.pem", directory / "key.pem"
    result = subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        capture_output=True,
        check=False,
    )
    return (cert, key) if result.returncode == 0 else None


class _GateHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, status, body, headers=None):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._json(401, {"detail": "invalid or missing helper token"})
        if self.path == "/v1/policy":
            return self._json(200, {"generated_at": "x", "grants": [grant(1, ALICE, "read")]})
        return self._json(500, {"detail": "boom"})

    def do_POST(self):
        self._json(302, {}, {"Location": "https://evil.test/v1/approvals"})


class GateClientHttpsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="gate-https-")
        pair = _make_cert(Path(cls._tmp.name))
        if pair is None:
            cls._tmp.cleanup()
            raise unittest.SkipTest("openssl with -addext unavailable")
        cls.cert, key = pair
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _GateHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cls.cert), str(key))
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls._tmp.cleanup()

    def client(self, token=TOKEN, trusted=True):
        ctx = ssl.create_default_context(cafile=str(self.cert)) if trusted else ssl.create_default_context()
        cfg = gate_client.GateConfig(f"https://localhost:{self.port}", token)
        return gate_client.GateClient(cfg, ssl_context=ctx, timeout=3)

    def test_policy_over_https(self) -> None:
        self.assertEqual(self.client().policy()["grants"][0]["handle"], ALICE)

    def test_redirect_is_refused(self) -> None:
        with self.assertRaisesRegex(gate_client.GateUnavailable, "redirect"):
            self.client().create_approval("send", {"handle": ALICE})

    def test_untrusted_certificate_fails_closed(self) -> None:
        with self.assertRaises(gate_client.GateUnavailable):
            self.client(trusted=False).policy()

    def test_wrong_token_and_server_error_fail_closed(self) -> None:
        with self.assertRaises(gate_client.GateUnavailable) as caught:
            self.client(token="w" * 32).policy()
        self.assertNotIn("w" * 32, str(caught.exception))
        with self.assertRaises(gate_client.GateUnavailable):
            self.client().get_approval(str(uuid.uuid4()))

    def test_unreachable_gate(self) -> None:
        with socket_closed_port() as port:
            cfg = gate_client.GateConfig(f"https://localhost:{port}", TOKEN)
            with self.assertRaises(gate_client.GateUnavailable):
                gate_client.GateClient(cfg, timeout=2).policy()


class socket_closed_port:
    def __enter__(self):
        import socket

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        return self.port

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------------
# Gate context from gate.json
# ---------------------------------------------------------------------------
class GateContextTests(unittest.TestCase):
    def _ctx_for(self, data: dict):
        with tempfile.TemporaryDirectory(prefix="gate-json-") as td:
            path = Path(td) / "gate.json"
            path.write_text(json.dumps(data))
            path.chmod(0o600)
            with mock.patch.dict(os.environ, {"IMESSAGE_GATE_PATH": str(path)}):
                return helper._build_gate_context()

    def test_no_gate_section_keeps_legacy_mode(self) -> None:
        ctx = self._ctx_for({"contact_ref_hmac_key": "k"})
        self.assertFalse(ctx.enabled)

    def test_configured_gate(self) -> None:
        ctx = self._ctx_for({"contact_ref_hmac_key": "k", "gate_url": "https://gate.test", "helper_token": TOKEN})
        self.assertTrue(ctx.enabled)
        self.assertIsNone(ctx.error)
        self.assertEqual(ctx.client.config.host, "gate.test")

    def test_misconfigured_gate_fails_closed_not_legacy(self) -> None:
        for data in (
            {"contact_ref_hmac_key": "k", "gate_url": "https://gate.test"},
            {"contact_ref_hmac_key": "k", "gate_url": "http://gate.test", "helper_token": TOKEN},
        ):
            with self.subTest(data=data):
                ctx = self._ctx_for(data)
                self.assertTrue(ctx.enabled)
                self.assertIsNone(ctx.client)
                policy = helper.load_gate_policy(ctx)
                self.assertEqual(policy.source, "gate")
                self.assertEqual(policy.allowlist, ())
                self.assertIn("misconfigured", policy.gate_error)

    def test_manager_role_never_uses_gate(self) -> None:
        with mock.patch.dict(os.environ, {"IMESSAGE_BRIDGE_ROLE": "manager"}):
            self.assertFalse(helper._build_gate_context().enabled)


# ---------------------------------------------------------------------------
# Policy mapping and fail-closed behavior
# ---------------------------------------------------------------------------
class PolicyMappingTests(GateModeTestCase):
    grants = [
        grant(1, ALICE, "read"),
        grant(2, ALICE, "send", "2999-01-01T00:00:00+00:00"),
        grant(3, CAROL, "watch"),
        grant(4, BOB, "read", "2000-01-01T00:00:00+00:00"),  # expired: dropped client-side too
        {"id": "bad", "handle": BOB, "scope": "read"},
        {"id": 5, "handle": BOB, "scope": "admin"},
    ]

    def test_scopes_map_to_policy(self) -> None:
        policy = self.policy()
        self.assertEqual(policy.source, "gate")
        self.assertEqual(policy.mode, "allowlist")
        self.assertEqual(policy.read, (ALICE,))
        self.assertEqual(policy.allowlist, (ALICE,))
        self.assertEqual(policy.send, (ALICE,))
        self.assertEqual(policy.watch, (CAROL,))
        self.assertEqual([g["id"] for g in policy.grants], [1, 2, 3])
        self.assertIsNone(policy.gate_error)

    def test_local_blocklist_wins_over_grants(self) -> None:
        self.blocklist.write_text("(415) 555-1234\n")
        policy = self.policy()
        self.assertFalse(helper.is_read_allowed(ALICE, ALICE, policy))
        with self.assertRaisesRegex(ValueError, "blocked"):
            self.run_action("send", {"contact_ref": self.ref("4155551234"), "text": "hi"})
        self.assertEqual(self.scripts, [])

    def test_gate_down_fails_closed(self) -> None:
        self.gate.fail = gate_client.GateUnavailable("gate unreachable: timed out")
        policy = self.policy()
        self.assertEqual(policy.allowlist, ())
        self.assertEqual(policy.send, ())
        self.assertIn("timed out", policy.gate_error)
        self.assertFalse(helper.is_read_allowed(ALICE, ALICE, policy))
        with self.assertRaisesRegex(RuntimeError, "gate unavailable"):
            helper.action_send({"to": ALICE, "text": "hi"}, None, CONTACTS, policy)
        with self.assertRaisesRegex(RuntimeError, "gate unavailable"):
            helper.action_send_commit({"approval_id": str(uuid.uuid4())}, None, CONTACTS, policy)
        self.assertEqual(self.scripts, [])
        lookup = helper.action_contacts_lookup({"name": "Alice"}, None, CONTACTS, policy)
        self.assertEqual(lookup["matches"][0]["scopes"], [])
        self.assertIn("gate_error", lookup)


class ReadScopeTests(GateModeTestCase):
    grants = [grant(1, ALICE, "read"), grant(2, CAROL, "watch")]

    def setUp(self) -> None:
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory(prefix="gate-read-")
        self.addCleanup(self._tmp.cleanup)
        db = Path(self._tmp.name) / "chat.db"
        build_fixture_db(db)
        self.conn = sqlite3.connect(str(db))
        self.conn.text_factory = bytes
        self.addCleanup(self.conn.close)

    def test_search_and_history_need_read(self) -> None:
        result = self.run_action("search", {"term": "SENTINEL", "days": 30}, self.conn)
        self.assertEqual({m["chat_id"] for m in result["matches"]}, {ALICE})
        history = self.run_action("chat_history", {"chat": "Carol", "days": 30}, self.conn)
        self.assertEqual(history["count"], 0)

    def test_review_needs_watch(self) -> None:
        result = self.run_action("review", {"days": 30}, self.conn)
        chats = {e["chat_id"] for bucket in ("needs_reply", "low_priority") for e in result[bucket]}
        self.assertNotIn(ALICE, chats)
        self.assertTrue(chats)
        self.assertTrue(all(c.startswith("chat") for c in chats))

    def test_contacts_lookup_reports_scopes(self) -> None:
        result = self.run_action("contacts_lookup", {"name": "Example"})
        scopes = {m["name"]: m["scopes"] for m in result["matches"]}
        self.assertEqual(scopes["Alice Example"], ["read"])
        self.assertEqual(scopes["Carol Example"], ["watch"])
        self.assertEqual(scopes["Bob Example"], [])
        self.assertNotIn("4155551234", json.dumps(result))


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------
class SendTests(GateModeTestCase):
    grants = [grant(7, ALICE, "send")]

    def test_granted_send_goes_out_immediately(self) -> None:
        result = self.run_action("send", {"contact_ref": self.ref("4155551234"), "text": "on my way"})
        self.assertEqual(result["status"], "sent")
        self.assertEqual(result["sent"]["via"], "send_grant")
        self.assertEqual(len(self.scripts), 1)
        self.assertIn(f'buddy "{ALICE}"', self.scripts[0])
        self.assertIn('"on my way"', self.scripts[0])
        self.assertEqual(self.gate.approvals, {})
        self.assertEqual(self.gate.audits[0][0], "send")
        self.assertEqual(self.gate.audits[0][1]["handle"], ALICE)
        self.assertNotIn(ALICE, json.dumps(result))

    def test_ungranted_send_creates_approval_and_sends_nothing(self) -> None:
        result = self.run_action(
            "send", {"contact_ref": self.ref("4155559876"), "text": "hi Carol", "service": "SMS"}
        )
        self.assertEqual(result["status"], "pending_approval")
        self.assertEqual(self.scripts, [])
        stored = self.gate.approvals[result["approval_id"]]
        self.assertEqual(stored["kind"], "send")
        self.assertEqual(
            stored["payload"],
            {"handle": CAROL, "display_name": "Carol Example", "service": "SMS", "text": "hi Carol"},
        )
        self.assertTrue(result["approve_url"].endswith(result["approval_id"]))
        self.assertEqual(result["recipient"]["contact_ref"], self.ref("4155559876"))
        self.assertNotIn(CAROL, json.dumps(result))

    def test_unknown_recipient_gets_placeholder_name(self) -> None:
        result = self.run_action("send", {"to": "+44 20 7946 0958", "text": "hello"})
        payload = self.gate.approvals[result["approval_id"]]["payload"]
        self.assertEqual(payload["handle"], "+442079460958")
        self.assertEqual(payload["display_name"], helper.UNKNOWN_CONTACT_NAME)

    def test_preview_reports_authorization_without_sending(self) -> None:
        granted = self.run_action("send_preview", {"contact_ref": self.ref("4155551234"), "text": "x"})
        self.assertEqual(granted["authorization"], "send_grant")
        pending = self.run_action("send_preview", {"contact_ref": self.ref("4155559876"), "text": "x"})
        self.assertEqual(pending["authorization"], "approval_required")
        self.assertNotIn("send_nonce", pending)
        self.assertEqual(self.scripts, [])
        self.assertEqual(self.gate.approvals, {})

    def test_rate_limit_is_reported(self) -> None:
        self.gate.create_approval = mock.Mock(
            side_effect=gate_client.GateError(429, "too many", {"retry-after": "120"})
        )
        with self.assertRaisesRegex(RuntimeError, "retry in 120s"):
            self.run_action("send", {"contact_ref": self.ref("4155559876"), "text": "x"})


class SendCommitTests(GateModeTestCase):
    def _pending(self, text="the approved text"):
        result = self.run_action("send", {"contact_ref": self.ref("4155559876"), "text": text})
        return result["approval_id"]

    def test_pending_approval_does_not_send(self) -> None:
        aid = self._pending()
        result = self.run_action("send_commit", {"approval_id": aid})
        self.assertEqual(result, {"status": "pending_approval", "approval_id": aid})
        self.assertEqual(self.scripts, [])

    def test_commit_sends_gate_stored_payload_once(self) -> None:
        aid = self._pending()
        self.gate.approve(aid)
        result = self.run_action(
            "send_commit",
            {"approval_id": aid, "text": "SWAPPED", "to": "+15555550100", "contact_ref": "x"},
        )
        self.assertEqual(result["status"], "sent")
        self.assertEqual(result["sent"]["approval_id"], aid)
        self.assertEqual(len(self.scripts), 1)
        self.assertIn('"the approved text"', self.scripts[0])
        self.assertIn(f'buddy "{CAROL}"', self.scripts[0])
        self.assertNotIn("SWAPPED", self.scripts[0])
        self.assertNotIn("5555550100", self.scripts[0])
        audit = self.gate.audits[-1]
        self.assertEqual(audit[1]["approval_id"], aid)
        with self.assertRaisesRegex(ValueError, "consumed"):
            self.run_action("send_commit", {"approval_id": aid})
        self.assertEqual(len(self.scripts), 1)

    def test_denied_and_expired(self) -> None:
        for status in ("denied", "expired"):
            aid = self._pending(text=f"text {status}")
            self.gate.approvals[aid]["status"] = status
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, status):
                self.run_action("send_commit", {"approval_id": aid})
        self.assertEqual(self.scripts, [])

    def test_unknown_or_malformed_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.run_action("send_commit", {"approval_id": str(uuid.uuid4())})
        with self.assertRaisesRegex(ValueError, "UUID"):
            self.run_action("send_commit", {"approval_id": "../../policy"})

    def test_blocklist_checked_at_commit(self) -> None:
        aid = self._pending()
        self.gate.approve(aid)
        self.blocklist.write_text(CAROL + "\n")
        with self.assertRaisesRegex(ValueError, "blocked"):
            self.run_action("send_commit", {"approval_id": aid})
        self.assertEqual(self.scripts, [])

    def test_malformed_gate_payload_is_refused(self) -> None:
        aid = self._pending()
        self.gate.approve(aid, {"handle": "chat123456", "display_name": "x", "service": "iMessage", "text": "hi"})
        with self.assertRaises(ValueError):
            self.run_action("send_commit", {"approval_id": aid})
        self.assertEqual(self.scripts, [])


# ---------------------------------------------------------------------------
# Grants
# ---------------------------------------------------------------------------
class GrantTests(GateModeTestCase):
    grants = [grant(11, ALICE, "watch", "2999-01-01T00:00:00+00:00"), grant(12, ALICE, "read"), grant(13, BOB, "send")]

    def test_request_grant(self) -> None:
        result = self.run_action(
            "request_grant",
            {"contact_ref": self.ref("4155559876"), "scopes": ["watch", "read", "watch"], "duration": "1w"},
        )
        self.assertEqual(result["status"], "pending_approval")
        self.assertEqual(result["scopes"], ["read", "watch"])
        self.assertEqual(result["duration_seconds"], 604800)
        payload = self.gate.approvals[result["approval_id"]]["payload"]
        self.assertEqual(
            payload,
            {"handle": CAROL, "display_name": "Carol Example", "scopes": ["read", "watch"], "duration_seconds": 604800},
        )
        permanent = self.run_action(
            "request_grant", {"contact_ref": self.ref(BOB), "scopes": "send", "duration": "always"}
        )
        self.assertIsNone(self.gate.approvals[permanent["approval_id"]]["payload"]["duration_seconds"])

    def test_request_grant_validation(self) -> None:
        ref = self.ref("4155559876")
        for params in (
            {"contact_ref": ref, "scopes": [], "duration": "1d"},
            {"contact_ref": ref, "scopes": ["admin"], "duration": "1d"},
            {"contact_ref": ref, "scopes": ["read"]},
            {"contact_ref": ref, "scopes": ["read"], "duration": "30s"},
            {"contact_ref": ref, "scopes": ["read"], "duration": "2y"},
            {"contact_ref": ref, "scopes": ["read"], "duration": 10**9},
            {"contact_ref": "0" * 64, "scopes": ["read"], "duration": "1d"},
        ):
            with self.subTest(params=params), self.assertRaises(ValueError):
                self.run_action("request_grant", params)
        self.assertEqual(self.gate.approvals, {})

    def test_approval_status(self) -> None:
        result = self.run_action(
            "request_grant", {"contact_ref": self.ref("4155559876"), "scopes": ["watch"], "duration": "1d"}
        )
        aid = result["approval_id"]
        self.assertEqual(self.run_action("approval_status", {"approval_id": aid})["status"], "pending")
        self.gate.approvals[aid].update(status="approved", grants=[{"id": 99, "scope": "watch", "expires_at": "x", "handle": CAROL}])
        status = self.run_action("approval_status", {"approval_id": aid})
        self.assertEqual(status["grants"], [{"grant_id": 99, "scope": "watch", "expires_at": "x"}])
        self.assertNotIn(CAROL, json.dumps(status))

    def test_list_grants_is_masked(self) -> None:
        result = self.run_action("list_grants", {})
        self.assertEqual(result["count"], 3)
        blob = json.dumps(result)
        for raw in (ALICE, "4155551234", BOB):
            self.assertNotIn(raw, blob)
        alice = [g for g in result["grants"] if g["name"] == "Alice Example"]
        self.assertEqual({g["scope"] for g in alice}, {"watch", "read"})
        self.assertEqual({g["contact_ref"] for g in alice}, {self.ref("4155551234")})
        self.assertEqual(alice[0]["label"], "mobile")
        lookup = self.run_action("contacts_lookup", {"name": "Alice"})
        self.assertEqual(lookup["matches"][0]["contact_ref"], alice[0]["contact_ref"])

    def test_revoke_by_id(self) -> None:
        result = self.run_action("revoke_grant", {"grant_id": 13})
        self.assertEqual(self.gate.revoked, [13])
        self.assertEqual(result["revoked"][0]["grant_id"], 13)

    def test_revoke_by_contact_ref_and_scope(self) -> None:
        self.run_action("revoke_grant", {"contact_ref": self.ref("4155551234"), "scope": "watch"})
        self.assertEqual(self.gate.revoked, [11])
        self.gate.revoked.clear()
        self.run_action("revoke_grant", {"contact_ref": self.ref("4155551234")})
        self.assertEqual(sorted(self.gate.revoked), [11, 12])
        with self.assertRaisesRegex(ValueError, "no active grants"):
            self.run_action("revoke_grant", {"contact_ref": self.ref("4155559876")})
        for bad in ({}, {"grant_id": 1, "contact_ref": "x"}, {"grant_id": True}, {"grant_id": 1, "scope": "admin"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.run_action("revoke_grant", bad)


# ---------------------------------------------------------------------------
# Watch: inbox and watch_tick
# ---------------------------------------------------------------------------
class WatchTests(GateModeTestCase):
    grants = [grant(21, CAROL, "watch"), grant(22, ALICE, "read")]

    def setUp(self) -> None:
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory(prefix="gate-watch-")
        self.addCleanup(self._tmp.cleanup)
        self.db = Path(self._tmp.name) / "chat.db"
        build_fixture_db(self.db)
        self.conn = sqlite3.connect(str(self.db))
        self.conn.text_factory = bytes
        self.addCleanup(self.conn.close)

    def add_message(self, rowid, handle_rowid, chat_rowid, text, is_from_me=0):
        self.conn.execute(
            "INSERT INTO message VALUES (?, ?, ?, ?, ?, ?)",
            (rowid, helper.to_apple_ns(time.time()), text, None, is_from_me, handle_rowid),
        )
        self.conn.execute("INSERT INTO chat_message_join VALUES (?, ?)", (chat_rowid, rowid))
        self.conn.commit()

    def test_inbox_returns_only_watched_senders_masked(self) -> None:
        result = self.run_action("inbox", {"cursor": 0}, self.conn)
        # Carol sent rowids 3 (group) and 5 (group); Alice (read only) and Bob are excluded.
        self.assertEqual([m["message_id"] for m in result["messages"]], [3, 5])
        self.assertTrue(all(m["name"] == "Carol Example" for m in result["messages"]))
        self.assertTrue(all(m["is_group"] for m in result["messages"]))
        self.assertEqual(result["messages"][0]["contact_ref"], self.ref("4155559876"))
        blob = json.dumps(result)
        for raw in (CAROL, "4155559876", "chat100200300", ALICE, BOB):
            self.assertNotIn(raw, blob)
        self.assertEqual(result["next_cursor"], 6)
        self.assertFalse(result["has_more"])

    def test_inbox_saved_cursor_advances(self) -> None:
        first = self.run_action("inbox", {}, self.conn)  # first run: last 24h only
        self.assertEqual(first["messages"], [])
        self.add_message(7, 2, 1, "hello from carol")
        self.add_message(8, 1, 1, "hello from alice")
        self.add_message(9, None, 1, "my reply", is_from_me=1)
        second = self.run_action("inbox", {}, self.conn)
        self.assertEqual([m["text"] for m in second["messages"]], ["hello from carol"])
        self.assertEqual(second["next_cursor"], 9)
        self.assertEqual(self.run_action("inbox", {}, self.conn)["messages"], [])
        # An explicit cursor reads without moving the saved one.
        replay = self.run_action("inbox", {"cursor": 6}, self.conn)
        self.assertEqual(len(replay["messages"]), 1)
        self.assertEqual(helper._load_watch_state()["inbox_cursor"], 9)

    def test_inbox_limit_and_has_more(self) -> None:
        result = self.run_action("inbox", {"cursor": 0, "limit": 1}, self.conn)
        self.assertEqual([m["message_id"] for m in result["messages"]], [3])
        self.assertTrue(result["has_more"])
        self.assertEqual(result["next_cursor"], 3)
        for bad in (0, 1000, "x"):
            with self.subTest(limit=bad), self.assertRaises(ValueError):
                self.run_action("inbox", {"cursor": 0, "limit": bad}, self.conn)
        with self.assertRaises(ValueError):
            self.run_action("inbox", {"cursor": -1}, self.conn)

    def test_inbox_redacts(self) -> None:
        self.add_message(7, 2, 1, "your code is 123456 verification code")
        result = self.run_action("inbox", {"cursor": 6}, self.conn)
        self.assertNotIn("123456", json.dumps(result))

    def test_watch_tick_counts_without_content(self) -> None:
        first = self.run_action("watch_tick", {}, self.conn)
        self.assertEqual(first, {"new_count": 0, "initialized": True, "capped": False})
        self.add_message(7, 2, 1, "carol 1")
        self.add_message(8, 2, 2, "carol 2 in group")
        self.add_message(9, 1, 1, "alice (read only)")
        self.add_message(10, 3, 2, "bob")
        self.add_message(11, None, 1, "me", is_from_me=1)
        tick = self.run_action("watch_tick", {}, self.conn)
        self.assertEqual(tick, {"new_count": 2, "initialized": False, "capped": False})
        self.assertNotIn(TEXT_SENTINEL, json.dumps(tick))
        self.assertEqual(self.run_action("watch_tick", {}, self.conn)["new_count"], 0)

    def test_watch_tick_after_revoke_counts_nothing(self) -> None:
        self.run_action("watch_tick", {}, self.conn)
        self.gate.grants = [grant(22, ALICE, "read")]
        self.add_message(7, 2, 1, "carol after revoke")
        self.assertEqual(self.run_action("watch_tick", {}, self.conn)["new_count"], 0)

    def test_watch_state_tampering_resets_safely(self) -> None:
        self.run_action("watch_tick", {}, self.conn)
        helper._save_watch_state({"tick_cursor": "../../etc", "inbox_cursor": -5})
        tick = self.run_action("watch_tick", {}, self.conn)
        self.assertTrue(tick["initialized"])

    def test_process_request_uses_direct_connection(self) -> None:
        with mock.patch.object(helper, "open_chatdb_direct", return_value=sqlite3.connect(str(self.db))) as direct, \
                mock.patch.object(helper, "copy_chatdb") as snapshot:
            req_dir = helper.REQUESTS_DIR
            for directory in (req_dir.parent, req_dir, helper.RESPONSES_DIR):
                directory.mkdir(mode=0o700, exist_ok=True)
            name = f"request-{uuid.uuid4().hex}.json"
            (req_dir / name).write_text(json.dumps({"id": "t", "action": "watch_tick", "params": {}}))
            helper.process_request(req_dir / name, self.policy())
        direct.assert_called_once()
        snapshot.assert_not_called()
        response = helper.RESPONSES_DIR / f"response-{name[len('request-'):-len('.json')]}.json"
        self.assertTrue(json.loads(response.read_text())["ok"])


# ---------------------------------------------------------------------------
# Gate required for gate-only actions; status never leaks the token
# ---------------------------------------------------------------------------
class LegacyModeTests(unittest.TestCase):
    def test_gate_actions_refuse_without_gate(self) -> None:
        saved = helper._GATE_CONTEXT
        helper._GATE_CONTEXT = helper.GateContext()
        self.addCleanup(setattr, helper, "_GATE_CONTEXT", saved)
        local = helper.PrivacyPolicy(mode="allowlist", blocklist=(), allowlist=())
        for action in ("send_commit", "request_grant", "approval_status", "list_grants", "revoke_grant", "inbox", "watch_tick"):
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "not configured"):
                helper.ACTIONS[action]({}, None, {}, local)
        self.assertEqual(helper.action_status({}, None, {}, local)["gate"], {"configured": False})


class StatusTests(GateModeTestCase):
    grants = [grant(1, ALICE, "read"), grant(2, ALICE, "send")]

    def test_status_reports_gate_without_token(self) -> None:
        status = helper.action_status({}, None, {}, self.policy())
        self.assertEqual(status["gate"]["host"], "gate.test")
        self.assertTrue(status["gate"]["reachable"])
        self.assertEqual(status["gate"]["grant_counts"], {"send": 1, "read": 1, "watch": 0})
        self.assertEqual(status["read_policy"]["source"], "gate")
        self.assertEqual(status["protocol_version"], "1.3")
        self.assertNotIn(TOKEN, json.dumps(status))


# ---------------------------------------------------------------------------
# configure_gate.py (run by the installer as root)
# ---------------------------------------------------------------------------
class ConfigureGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="configure-gate-")
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "gate.json"

    def run_tool(self, argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO(stdin)), redirect_stdout(out), redirect_stderr(err):
            code = configure_gate.main(["--gate-json", str(self.path), *argv])
        return code, out.getvalue() + err.getvalue()

    def test_creates_file_with_key_and_private_mode(self) -> None:
        code, output = self.run_tool([])
        self.assertEqual(code, 0)
        data = json.loads(self.path.read_text())
        self.assertGreaterEqual(len(data["contact_ref_hmac_key"]), 32)
        self.assertNotIn("gate_url", data)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertIn("no approval gate", output)

    def test_sets_gate_and_never_prints_token(self) -> None:
        self.path.write_text(json.dumps({"schema_version": 1, "contact_ref_hmac_key": "keep-me"}))
        code, output = self.run_tool(
            ["--gate-url", "https://imessage-gate.example-tailnet.ts.net/", "--token-stdin"], stdin=TOKEN + "\n"
        )
        self.assertEqual(code, 0)
        data = json.loads(self.path.read_text())
        self.assertEqual(data["contact_ref_hmac_key"], "keep-me")
        self.assertEqual(data["gate_url"], "https://imessage-gate.example-tailnet.ts.net")
        self.assertEqual(data["helper_token"], TOKEN)
        self.assertNotIn(TOKEN, output)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        # Re-running without gate args keeps the gate section.
        self.run_tool([])
        self.assertEqual(json.loads(self.path.read_text())["helper_token"], TOKEN)

    def test_placeholder_key_is_replaced(self) -> None:
        self.path.write_text(json.dumps({"schema_version": 1, "contact_ref_hmac_key": "REPLACE_ON_INSTALL"}))
        self.run_tool([])
        self.assertNotEqual(json.loads(self.path.read_text())["contact_ref_hmac_key"], "REPLACE_ON_INSTALL")

    def test_rejects_bad_input_without_writing(self) -> None:
        self.path.write_text(json.dumps({"contact_ref_hmac_key": "k"}))
        before = self.path.read_text()
        for argv, stdin in (
            (["--gate-url", "http://gate.test", "--token-stdin"], TOKEN),
            (["--gate-url", "https://gate.test", "--token-stdin"], "short"),
        ):
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                self.run_tool(argv, stdin)
        self.assertEqual(self.path.read_text(), before)
        with self.assertRaises(SystemExit):
            self.run_tool(["--gate-url", "https://gate.test"])

    def test_refuses_symlink(self) -> None:
        target = Path(self._tmp.name) / "elsewhere.json"
        target.write_text("{}")
        self.path.symlink_to(target)
        with self.assertRaises(SystemExit):
            self.run_tool([])

    def test_disable(self) -> None:
        self.path.write_text(json.dumps({"contact_ref_hmac_key": "k", "gate_url": "https://g.test", "helper_token": TOKEN}))
        self.run_tool(["--disable"])
        data = json.loads(self.path.read_text())
        self.assertNotIn("helper_token", data)
        self.assertEqual(data["contact_ref_hmac_key"], "k")


class InstallerGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.script = (REPO_ROOT / "install-hardened.sh").read_text()

    def test_token_is_read_hidden_and_passed_on_stdin(self) -> None:
        self.assertIn("read -r -s -p", self.script)
        self.assertIn('printf \'%s\\n\' "$GATE_TOKEN_INPUT" | sudo "$PYTHON3_PATH" -I "$CONFIGURE_GATE"', self.script)
        for line in self.script.splitlines():
            if "GATE_TOKEN_INPUT" in line and "echo" in line:
                self.fail(f"token may be echoed: {line.strip()}")
        self.assertNotIn("--token ", self.script)

    def test_gate_client_is_installed_and_validated(self) -> None:
        self.assertIn('-DGATE_CLIENT_SCRIPT="\\"$GATE_CLIENT_PY\\""', self.script)
        self.assertIn('"$SOURCE_ROOT/bin/gate_client.py" "$GATE_CLIENT_PY"', self.script)
        self.assertIn('"$SOURCE_ROOT/bin/gate_client.py" \\', self.script)

    def test_installer_syntax(self) -> None:
        result = subprocess.run(["bash", "-n", str(REPO_ROOT / "install-hardened.sh")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(shutil.which("clang"), "clang required")
class WrapperGateClientTests(unittest.TestCase):
    def test_wrapper_validates_and_exports_gate_client(self) -> None:
        with tempfile.TemporaryDirectory(prefix="grokbot-wrapper-gate-") as td:
            root = Path(td)
            helper_script = root / "helper.py"
            send_gate = root / "send_gate.py"
            gate = root / "gate_client.py"
            confirmation = root / "confirm"
            wrapper = root / "wrapper"
            helper_script.write_text("import os\nprint(os.environ['IMESSAGE_GATE_CLIENT_PATH'])\n")
            send_gate.write_text("# fixture\n")
            gate.write_text("# fixture\n")
            confirmation.write_text("#!/bin/sh\nexit 0\n")
            for path, mode in ((helper_script, 0o500), (send_gate, 0o500), (gate, 0o500), (confirmation, 0o700)):
                path.chmod(mode)
            compiled = subprocess.run(
                [
                    "clang", "-Wall", "-Wextra", "-Werror", "-O2",
                    f'-DHELPER_SCRIPT="{helper_script}"',
                    f'-DSEND_GATE_SCRIPT="{send_gate}"',
                    f'-DGATE_CLIENT_SCRIPT="{gate}"',
                    f'-DCONFIRM_HELPER="{confirmation}"',
                    f'-DBRIDGE_ROOT="{root / "bridge"}"',
                    f'-DPYTHON_INTERPRETER="{sys.executable}"',
                    "-o", str(wrapper), str(REPO_ROOT / "bin" / "imessage_helper.c"),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ok = subprocess.run([str(wrapper)], capture_output=True, text=True, check=False)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(ok.stdout.strip(), str(gate))
            gate.chmod(0o520)
            bad = subprocess.run([str(wrapper)], capture_output=True, text=True, check=False)
            self.assertEqual(bad.returncode, 5)
            self.assertIn("gate-client module", bad.stderr)


if __name__ == "__main__":
    unittest.main()
