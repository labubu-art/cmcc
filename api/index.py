# Vercel-deployable Flask wrapper for the existing server implementation.
# This file exposes a WSGI `app` variable so Vercel can run it as a Python serverless function.

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from flask import Flask, Response, jsonify, make_response, request

# Ensure the original server/ directory is importable so we can reuse build_cmcc_request
HERE = Path(__file__).resolve().parent.parent / "server"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import build_cmcc_request as builder  # type: ignore

TEMPLATE_PATH = HERE / "index.html.template"
MAX_JSON_BODY = 16 * 1024
FLOW_ID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"


class ServiceError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class AppConfig:
    forced_ipv6: str | None = None
    webhook_token: str | None = None
    flow_ttl: int = 120
    allow_non_global_observed_ip: bool = False


@dataclass
class FlowRecord:
    flow_id: str
    created_at: float
    expires_at: float
    observed_ip: str | None = None
    webhook_request_id: str | None = None
    consumed: bool = False


def classify_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if isinstance(addr, ipaddress.IPv6Address):
        return "ipv4" if addr.ipv4_mapped is not None else "ipv6"
    return "ipv4"


def validate_observed_ipv6(ip: str, allow_non_global: bool = False) -> str:
    candidate = ip.split("%", 1)[0].strip()
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ServiceError(422, "observed_ip 不是合法 IP 地址") from exc
    if not isinstance(addr, ipaddress.IPv6Address) or addr.ipv4_mapped is not None:
        raise ServiceError(422, "observed_ip 必须是原生 IPv6 地址")
    if not allow_non_global and not addr.is_global:
        raise ServiceError(422, "observed_ip 必须是全局单播 IPv6 地址")
    return addr.compressed


def validate_webhook_token(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise ValueError("WEBHOOK_SITE_TOKEN 必须是 UUID") from exc


class FlowStore:
    """A lightweight in-memory flow store.

    NOTE: On Vercel serverless functions this store is ephemeral. It may survive
    for warm instances but WILL be lost on cold starts. Use an external store
    for production reliability.
    """

    def __init__(self, ttl_seconds: int, allow_non_global_ip: bool = False) -> None:
        self.ttl_seconds = ttl_seconds
        self.allow_non_global_ip = allow_non_global_ip
        self._flows: dict[str, FlowRecord] = {}

    def _purge_expired(self, now: float) -> None:
        expired = [key for key, flow in self._flows.items() if flow.expires_at <= now]
        for key in expired:
            del self._flows[key]

    def create(self) -> FlowRecord:
        now = time.time()
        flow_id = str(uuid.uuid4())
        flow = FlowRecord(flow_id=flow_id, created_at=now, expires_at=now + self.ttl_seconds)
        self._purge_expired(now)
        if len(self._flows) >= 1024:
            raise ServiceError(503, "活动 flow 已达到上限，请稍后重试")
        self._flows[flow_id] = flow
        return flow

    def _get_locked(self, flow_id: str, now: float) -> FlowRecord:
        flow = self._flows.get(flow_id)
        if flow is None:
            raise ServiceError(404, "flow 不存在或已过期")
        if flow.expires_at <= now:
            del self._flows[flow_id]
            raise ServiceError(410, "flow 已过期")
        return flow

    def observe(self, flow_id: str, observed_ip: str, webhook_request_id: str) -> dict[str, Any]:
        canonical_ip = validate_observed_ipv6(observed_ip, self.allow_non_global_ip)
        try:
            canonical_request_id = str(uuid.UUID(webhook_request_id))
        except ValueError as exc:
            raise ServiceError(422, "webhook_request_id 不是合法 UUID") from exc
        now = time.time()
        flow = self._get_locked(flow_id, now)
        if flow.consumed:
            raise ServiceError(409, "flow 已消费")
        if flow.webhook_request_id:
            if flow.webhook_request_id == canonical_request_id and flow.observed_ip == canonical_ip:
                return {"status": "ready", "duplicate": True}
            raise ServiceError(409, "flow 已绑定另一条 webhook 观测")
        flow.observed_ip = canonical_ip
        flow.webhook_request_id = canonical_request_id
        return {"status": "ready", "duplicate": False}

    def status(self, flow_id: str) -> dict[str, Any]:
        now = time.time()
        flow = self._get_locked(flow_id, now)
        if flow.consumed:
            state = "consumed"
        elif flow.observed_ip:
            state = "ready"
        else:
            state = "pending"
        return {
            "flow_id": flow.flow_id,
            "status": state,
            "observed_ip": flow.observed_ip,
            "expires_in": max(0, int(flow.expires_at - now)),
        }

    def consume(self, flow_id: str) -> dict[str, object]:
        now = time.time()
        flow = self._get_locked(flow_id, now)
        if flow.consumed:
            raise ServiceError(409, "flow 已消费；请刷新页面创建新 flow")
        if not flow.observed_ip:
            raise ServiceError(409, "尚未收到 IPv6 观测结果")
        request_bundle = builder.build_request_bundle(flow.observed_ip, refresh_runtime=True)
        flow.consumed = True
        return request_bundle


def detect_client_ip_from_request(req) -> str:
    # Prefer X-Forwarded-For when behind proxies (Vercel sets this header)
    xff = req.headers.get("X-Forwarded-For")
    if xff:
        # Take the first IP
        return xff.split(",", 1)[0].split("%", 1)[0].strip()
    # Fall back to remote_addr
    remote = req.remote_addr or ""
    return remote.split("%", 1)[0].strip()


def json_for_script(value: Any) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_page(flow_config: dict[str, Any], initial_prefill: dict[str, object] | None) -> bytes:
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    template = template.replace("__FLOW_CONFIG_JSON__", json_for_script(flow_config))
    template = template.replace("__PREFILL_JSON__", json_for_script(initial_prefill))
    template = template.replace("__AES_KEY__", html.escape(builder.AES_KEY_B64, quote=True))
    template = template.replace("__AES_IV__", html.escape(builder.AES_IV_B64, quote=True))
    return template.encode("utf-8")


def read_json_body(req) -> dict[str, Any]:
    try:
        payload = req.get_data(cache=False, as_text=False)
    except Exception:
        raise ServiceError(400, "无法读取请求体")
    if not payload:
        raise ServiceError(413, "JSON 请求体为空或超过限制")
    if len(payload) > MAX_JSON_BODY:
        raise ServiceError(413, "JSON 请求体为空或超过 16 KiB")
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ServiceError(400, "JSON 请求体无效") from exc
    if not isinstance(data, dict):
        raise ServiceError(400, "JSON 请求体必须是对象")
    return data


def re_fullmatch_flow_id(value: str) -> bool:
    return re.fullmatch(FLOW_ID_RE, value) is not None


# Build Flask app and global store/config
app = Flask(__name__)

# Load config from environment for quick Vercel deploy
def make_config_from_env() -> AppConfig:
    forced_ipv6 = None
    if os.environ.get("CMCC_IPV6"):
        forced_ipv6 = validate_observed_ipv6(os.environ["CMCC_IPV6"], allow_non_global=True)
    webhook_token = None
    if os.environ.get("WEBHOOK_SITE_TOKEN"):
        webhook_token = validate_webhook_token(os.environ["WEBHOOK_SITE_TOKEN"])
    flow_ttl = int(os.environ.get("CMCC_FLOW_TTL", "120"))
    allow_non_global = os.environ.get("ALLOW_NON_GLOBAL_OBSERVED_IP") in ("1", "true", "True")
    return AppConfig(forced_ipv6=forced_ipv6, webhook_token=webhook_token, flow_ttl=flow_ttl, allow_non_global_observed_ip=allow_non_global)

APP_CONFIG = make_config_from_env()
FLOW_STORE = FlowStore(APP_CONFIG.flow_ttl, APP_CONFIG.allow_non_global_observed_ip)


@app.after_request
def set_security_headers(resp: Response) -> Response:  # type: ignore[override]
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers[
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "img-src https://webhook.site; connect-src 'self' https://rcs.cmpassport.com; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return resp


@app.errorhandler(ServiceError)
def handle_service_error(exc: ServiceError):
    return jsonify({"error": str(exc)}), exc.status


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})


@app.route("/whoami", methods=["GET"])
def whoami():
    ip = detect_client_ip_from_request(request)
    return jsonify({"ip": ip, "kind": classify_ip(ip)})


@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def index():
    if APP_CONFIG.webhook_token:
        flow = FLOW_STORE.create()
        webhook_url = (
            f"https://webhook.site/{APP_CONFIG.webhook_token}/cmcc-ip.gif?"
            + urlencode({"flow_id": flow.flow_id})
        )
        flow_config = {"mode": "webhook", "flow_id": flow.flow_id, "webhook_url": webhook_url, "expires_in": APP_CONFIG.flow_ttl}
        body = render_page(flow_config, None)
    else:
        peer_ip = APP_CONFIG.forced_ipv6 or detect_client_ip_from_request(request)
        prefill = builder.build_request_bundle(peer_ip, refresh_runtime=True)
        flow_config = {"mode": "direct", "observed_ip": peer_ip}
        body = render_page(flow_config, prefill)
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


def get_flow_id_or_400(flow_id: str) -> str:
    if not re_fullmatch_flow_id(flow_id):
        raise ServiceError(404, "Not Found")
    return flow_id


@app.route("/api/flows/<flow_id>/status", methods=["GET"])
def flow_status(flow_id: str):
    fid = get_flow_id_or_400(flow_id)
    return jsonify(FLOW_STORE.status(fid))


@app.route("/api/flows/<flow_id>/observation", methods=["POST"])
def flow_observation(flow_id: str):
    fid = get_flow_id_or_400(flow_id)
    payload = read_json_body(request)
    result = FLOW_STORE.observe(fid, str(payload.get("observed_ip") or ""), str(payload.get("webhook_request_id") or ""))
    return jsonify(result)


@app.route("/api/flows/<flow_id>/request", methods=["POST"])
def flow_request(flow_id: str):
    fid = get_flow_id_or_400(flow_id)
    payload = read_json_body(request)
    if payload.get("confirmed") is not True:
        raise ServiceError(400, "必须明确传入 confirmed=true")
    request_bundle = FLOW_STORE.consume(fid)
    return jsonify({"request": request_bundle})


@app.route("/api/flows/<flow_id>/decrypt", methods=["POST"])
def flow_decrypt(flow_id: str):
    fid = get_flow_id_or_400(flow_id)
    payload = read_json_body(request)
    result_data = payload.get("resultData")
    if not isinstance(result_data, str) or not result_data.strip():
        raise ServiceError(400, "resultData 必填且需为非空字符串")
    code = payload.get("resultCode")
    iv = payload.get("encryptedIV") if isinstance(payload.get("encryptedIV"), str) else None
    try:
        plaintext = builder.decrypt_result_data(result_data, iv_b64=iv)
    except Exception as exc:  # noqa: BLE001
        print(f"[cmcc-login-service] decrypt failed flow={fid} code={code}: {exc!r}", file=sys.stderr, flush=True)
        raise ServiceError(422, f"resultData 解密失败：{exc}") from exc
    print(f"[cmcc-login-service] decrypted flow={fid} code={code}: {plaintext}", file=sys.stderr, flush=True)
    return jsonify({"plaintext": plaintext})


# Expose only 'app' for Vercel WSGI adapter

# For local debugging with `flask run` you can set FLASK_APP=api/index.py and run
if __name__ == "__main__":
    # When running locally, ensure builder.runtime assets are fresh
    builder.apply_app_config(builder.load_app_config(os.environ.get("CMCC_APP_CONFIG")))
    print("Starting local Flask server on 0.0.0.0:8080")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), debug=False)
