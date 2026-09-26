"""Client for the imessage-gate approval service.

The helper holds only a helper token. With it the gate lets us read the
active grants, request approvals, consume an approved send, revoke grants,
and write audit entries. It can never approve or grant: only a passkey
assertion on the owner's phone can.

Transport rules:
  - stdlib urllib only, HTTPS only, to the single gate origin pinned in the
    root-owned gate.json;
  - redirects and environment proxies are refused;
  - bounded timeouts and response sizes;
  - the helper token is never logged or returned in a response.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_TIMEOUT_S = 5.0
MAX_RESPONSE_BYTES = 1024 * 1024
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~-]{20,256}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class GateConfigError(Exception):
    """gate.json has a gate section that is incomplete or unsafe."""


class GateUnavailable(Exception):
    """The gate could not be reached or answered with a server error."""


class GateError(Exception):
    """The gate rejected the request (4xx)."""

    def __init__(self, status: int, detail: Any, headers: dict[str, str] | None = None):
        self.status = status
        self.detail = detail
        self.headers = headers or {}
        super().__init__(f"gate returned {status}: {detail}")

    @property
    def detail_status(self) -> str | None:
        """The approval status carried by a 409 from consume, if any."""
        if isinstance(self.detail, dict):
            value = self.detail.get("status")
            return value if isinstance(value, str) else None
        return None


def canonical_json(payload: dict[str, Any]) -> str:
    """Must stay byte-identical to imessage_gate.models.canonical_json."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def validate_gate_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GateConfigError("gate_url must be a non-empty string")
    parts = urllib.parse.urlsplit(value.strip())
    if parts.scheme != "https":
        raise GateConfigError("gate_url must use https")
    if not parts.hostname or parts.username or parts.password:
        raise GateConfigError("gate_url must be a bare https origin")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise GateConfigError("gate_url must not include a path, query, or fragment")
    try:
        port = parts.port
    except ValueError as exc:
        raise GateConfigError(f"gate_url has an invalid port: {exc}") from exc
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port else "")


def validate_helper_token(value: Any) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.match(value):
        raise GateConfigError("helper_token must be 20-256 URL-safe characters")
    return value


def validate_approval_id(value: Any) -> str:
    if not isinstance(value, str) or not _UUID_RE.match(value.strip().lower()):
        raise ValueError("approval_id must be a UUID")
    return value.strip().lower()


class GateConfig:
    __slots__ = ("url", "helper_token")

    def __init__(self, url: str, helper_token: str):
        self.url = url
        self.helper_token = helper_token

    def __repr__(self) -> str:
        return f"GateConfig(url={self.url!r})"

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.url).hostname or ""


def config_from_gate_json(data: dict[str, Any]) -> GateConfig | None:
    """None when gate.json has no gate section (gate mode off).

    A partial or invalid section raises, so callers fail closed instead of
    silently falling back to legacy local policy.
    """
    url = data.get("gate_url")
    token = data.get("helper_token")
    if url in (None, "") and token in (None, ""):
        return None
    if url in (None, "") or token in (None, ""):
        raise GateConfigError("gate.json must set both gate_url and helper_token")
    return GateConfig(url=validate_gate_url(url), helper_token=validate_helper_token(token))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise GateUnavailable(f"gate attempted a redirect ({code}); refusing")


def _build_opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirect(),
    )


class GateClient:
    def __init__(
        self,
        config: GateConfig,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        ssl_context: ssl.SSLContext | None = None,
        opener: Any = None,
    ):
        self.config = config
        self.timeout = timeout
        self._opener = opener or _build_opener(ssl_context or ssl.create_default_context())

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        if not path.startswith("/v1/"):
            raise ValueError("gate path must be under /v1/")
        data = None
        headers = {
            "Authorization": f"Bearer {self.config.helper_token}",
            "Accept": "application/json",
            "User-Agent": "grokbot-imessage-helper",
        }
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.config.url + path, data=data, headers=headers, method=method
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                status = resp.status
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                resp_headers = dict(resp.headers.items())
        except urllib.error.HTTPError as exc:
            try:
                status = exc.code
                raw = exc.read(MAX_RESPONSE_BYTES + 1) if exc.fp else b""
                resp_headers = dict(exc.headers.items()) if exc.headers else {}
            finally:
                exc.close()
        except GateUnavailable:
            raise
        except (urllib.error.URLError, OSError, ssl.SSLError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            raise GateUnavailable(f"gate unreachable: {reason}") from None

        if len(raw) > MAX_RESPONSE_BYTES:
            raise GateUnavailable("gate response too large")
        try:
            decoded = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = None
            if 200 <= status < 300:
                raise GateUnavailable("gate returned malformed JSON") from None

        if 200 <= status < 300:
            return decoded
        detail = decoded.get("detail") if isinstance(decoded, dict) else decoded
        if status >= 500 or status in (401, 403):
            # 401/403 mean our token is wrong or the route is forbidden; treat
            # as unavailable so every caller fails closed the same way.
            raise GateUnavailable(f"gate returned {status}: {detail}")
        raise GateError(status, detail, resp_headers)

    def policy(self) -> dict[str, Any]:
        data = self._request("GET", "/v1/policy")
        if not isinstance(data, dict) or not isinstance(data.get("grants"), list):
            raise GateUnavailable("gate policy response is malformed")
        return data

    def create_approval(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if kind not in ("send", "grant"):
            raise ValueError("approval kind must be send or grant")
        data = self._request("POST", "/v1/approvals", {"kind": kind, "payload": payload})
        if not isinstance(data, dict) or "id" not in data:
            raise GateUnavailable("gate approval response is malformed")
        if data.get("payload_sha256") != payload_sha256(payload):
            raise GateUnavailable("gate stored a different payload than requested")
        return data

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        aid = validate_approval_id(approval_id)
        data = self._request("GET", f"/v1/approvals/{aid}")
        if not isinstance(data, dict):
            raise GateUnavailable("gate approval response is malformed")
        return data

    def consume(self, approval_id: str) -> dict[str, Any]:
        """approved -> consumed; returns the gate-stored payload, verified."""
        aid = validate_approval_id(approval_id)
        data = self._request("POST", f"/v1/approvals/{aid}/consume")
        if not isinstance(data, dict) or not isinstance(data.get("payload"), dict):
            raise GateUnavailable("gate consume response is malformed")
        if data.get("kind") != "send":
            raise GateUnavailable("gate consumed a non-send approval")
        if payload_sha256(data["payload"]) != data.get("payload_sha256"):
            raise GateUnavailable("gate payload hash mismatch; refusing to send")
        return data

    def revoke_grant(self, grant_id: int) -> dict[str, Any]:
        if isinstance(grant_id, bool) or not isinstance(grant_id, int) or grant_id <= 0:
            raise ValueError("grant_id must be a positive integer")
        return self._request("POST", f"/v1/grants/{grant_id}/revoke")

    def audit(
        self,
        event: str,
        *,
        handle: str | None = None,
        approval_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        body: dict[str, Any] = {"event": event}
        if handle:
            body["handle"] = handle
        if approval_id:
            body["approval_id"] = approval_id
        if detail:
            body["detail"] = detail
        self._request("POST", "/v1/audit", body)
