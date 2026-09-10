#!/usr/bin/env python3
"""CMCC 一键登录防御性验证服务。

支持两种模式：
1. 直连模式：从浏览器到本服务的 TCP 对端地址读取 IPv6。
2. Webhook flow 模式：用户显式触发 Webhook.site 探针，本机监听器把记录中的
   顶层 ``ip`` 作为 observed_ip 回传；用户再次确认后才生成 CMCC 请求。
"""
from __future__ import annotations

import argparse
import html
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_cmcc_request as builder  # noqa: E402

TEMPLATE_PATH = HERE / "index.html.template"
MAX_JSON_BODY = 16 * 1024
MAX_ACTIVE_FLOWS = 1024
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
    """返回 ipv6、ipv4 或 unknown；IPv4-mapped IPv6 视为 IPv4。"""
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
        raise ValueError("--webhook-token 必须是 UUID") from exc


class FlowStore:
    def __init__(
        self,
        ttl_seconds: int,
        allow_non_global_ip: bool = False,
        max_active: int = MAX_ACTIVE_FLOWS,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.allow_non_global_ip = allow_non_global_ip
        self.max_active = max_active
        self._lock = threading.Lock()
        self._flows: dict[str, FlowRecord] = {}

    def _purge_expired(self, now: float) -> None:
        expired = [key for key, flow in self._flows.items() if flow.expires_at <= now]
        for key in expired:
            del self._flows[key]

    def create(self) -> FlowRecord:
        now = time.time()
        flow_id = str(uuid.uuid4())
        flow = FlowRecord(
            flow_id=flow_id,
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            self._purge_expired(now)
            if len(self._flows) >= self.max_active:
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

    def observe(
        self, flow_id: str, observed_ip: str, webhook_request_id: str
    ) -> dict[str, Any]:
        canonical_ip = validate_observed_ipv6(
            observed_ip, self.allow_non_global_ip
        )
        try:
            canonical_request_id = str(uuid.UUID(webhook_request_id))
        except ValueError as exc:
            raise ServiceError(422, "webhook_request_id 不是合法 UUID") from exc

        now = time.time()
        with self._lock:
            flow = self._get_locked(flow_id, now)
            if flow.consumed:
                raise ServiceError(409, "flow 已消费")
            if flow.webhook_request_id:
                if (
                    flow.webhook_request_id == canonical_request_id
                    and flow.observed_ip == canonical_ip
                ):
                    return {"status": "ready", "duplicate": True}
                raise ServiceError(409, "flow 已绑定另一条 webhook 观测")
            flow.observed_ip = canonical_ip
            flow.webhook_request_id = canonical_request_id
            return {"status": "ready", "duplicate": False}

    def status(self, flow_id: str) -> dict[str, Any]:
        now = time.time()
        with self._lock:
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
        with self._lock:
            flow = self._get_locked(flow_id, now)
            if flow.consumed:
                raise ServiceError(409, "flow 已消费；请刷新页面创建新 flow")
            if not flow.observed_ip:
                raise ServiceError(409, "尚未收到 IPv6 观测结果")
            request_bundle = builder.build_request_bundle(
                flow.observed_ip, refresh_runtime=True
            )
            flow.consumed = True
            return request_bundle


def detect_client_ip(handler: BaseHTTPRequestHandler) -> str:
    candidate = handler.client_address[0].split("%", 1)[0].strip()
    try:
        addr = ipaddress.ip_address(candidate)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
    except ValueError:
        pass
    return candidate


def render_page(
    flow_config: dict[str, Any], initial_prefill: dict[str, object] | None
) -> bytes:
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    template = template.replace("__FLOW_CONFIG_JSON__", json_for_script(flow_config))
    template = template.replace("__PREFILL_JSON__", json_for_script(initial_prefill))
    template = template.replace(
        "__AES_KEY__", html.escape(builder.AES_KEY_B64, quote=True)
    )
    template = template.replace(
        "__AES_IV__", html.escape(builder.AES_IV_B64, quote=True)
    )
    return template.encode("utf-8")


def json_for_script(value: Any) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError as exc:
        raise ServiceError(400, "Content-Length 无效") from exc
    if length <= 0 or length > MAX_JSON_BODY:
        raise ServiceError(413, "JSON 请求体为空或超过 16 KiB")
    try:
        payload = json.loads(handler.rfile.read(length))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ServiceError(400, "JSON 请求体无效") from exc
    if not isinstance(payload, dict):
        raise ServiceError(400, "JSON 请求体必须是对象")
    return payload


class Handler(BaseHTTPRequestHandler):
    server_version = "cmcc-login-service/2.0"

    @property
    def app_config(self) -> AppConfig:
        return self.server.app_config  # type: ignore[attr-defined]

    @property
    def flow_store(self) -> FlowStore:
        return self.server.flow_store  # type: ignore[attr-defined]

    def _send_bytes(
        self, body: bytes, content_type: str, status: int = 200, extra_headers=None
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "img-src https://webhook.site; connect-src 'self' https://rcs.cmpassport.com; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        self._send_bytes(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            "application/json; charset=utf-8",
            status,
        )

    def _send_error_json(self, error: ServiceError) -> None:
        self._send_json({"error": str(error)}, error.status)

    def _decrypt_and_log(
        self, flow_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        result_data = payload.get("resultData")
        if not isinstance(result_data, str) or not result_data.strip():
            raise ServiceError(400, "resultData 必填且需为非空字符串")
        code = payload.get("resultCode")
        iv = payload.get("encryptedIV") if isinstance(payload.get("encryptedIV"), str) else None
        try:
            plaintext = builder.decrypt_result_data(result_data, iv_b64=iv)
        except Exception as exc:  # noqa: BLE001
            print(
                f"[cmcc-login-service] decrypt failed flow={flow_id} code={code}: {exc!r}",
                file=sys.stderr,
                flush=True,
            )
            raise ServiceError(422, f"resultData 解密失败：{exc}") from exc
        print(
            f"[cmcc-login-service] decrypted flow={flow_id} code={code}: {plaintext}",
            file=sys.stderr,
            flush=True,
        )
        return {"plaintext": plaintext}

    def _flow_parts(self, path: str, suffix: str) -> str | None:
        prefix = "/api/flows/"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        candidate = path[len(prefix) : -len(suffix)]
        try:
            flow_id = str(uuid.UUID(candidate))
        except ValueError:
            return None
        return flow_id if re_fullmatch_flow_id(flow_id) else None

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        try:
            if parsed.path == "/healthz":
                self._send_json({"status": "ok"})
                return
            if parsed.path in ("/", "/index.html"):
                self._serve_index()
                return
            if parsed.path == "/whoami":
                peer_ip = detect_client_ip(self)
                self._send_json({"ip": peer_ip, "kind": classify_ip(peer_ip)})
                return
            flow_id = self._flow_parts(parsed.path, "/status")
            if flow_id:
                self._send_json(self.flow_store.status(flow_id))
                return
            raise ServiceError(404, "Not Found")
        except ServiceError as exc:
            self._send_error_json(exc)
        except Exception as exc:  # noqa: BLE001
            print(f"[cmcc-login-service] GET failed: {exc!r}", file=sys.stderr)
            self._send_error_json(ServiceError(500, "Internal Server Error"))

    def _serve_index(self) -> None:
        config = self.app_config
        if config.webhook_token:
            flow = self.flow_store.create()
            webhook_url = (
                f"https://webhook.site/{config.webhook_token}/cmcc-ip.gif?"
                + urllib.parse.urlencode({"flow_id": flow.flow_id})
            )
            flow_config = {
                "mode": "webhook",
                "flow_id": flow.flow_id,
                "webhook_url": webhook_url,
                "expires_in": config.flow_ttl,
            }
            body = render_page(flow_config, None)
        else:
            peer_ip = config.forced_ipv6 or detect_client_ip(self)
            prefill = builder.build_request_bundle(peer_ip, refresh_runtime=True)
            flow_config = {"mode": "direct", "observed_ip": peer_ip}
            body = render_page(flow_config, prefill)
        self._send_bytes(body, "text/html; charset=utf-8")

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        try:
            flow_id = self._flow_parts(path, "/observation")
            if flow_id:
                payload = read_json_body(self)
                result = self.flow_store.observe(
                    flow_id,
                    str(payload.get("observed_ip") or ""),
                    str(payload.get("webhook_request_id") or ""),
                )
                self._send_json(result)
                return

            flow_id = self._flow_parts(path, "/request")
            if flow_id:
                payload = read_json_body(self)
                if payload.get("confirmed") is not True:
                    raise ServiceError(400, "必须明确传入 confirmed=true")
                request_bundle = self.flow_store.consume(flow_id)
                self._send_json({"request": request_bundle})
                return

            flow_id = self._flow_parts(path, "/decrypt")
            if flow_id:
                payload = read_json_body(self)
                result = self._decrypt_and_log(flow_id, payload)
                self._send_json(result)
                return
            raise ServiceError(404, "Not Found")
        except ServiceError as exc:
            self._send_error_json(exc)
        except Exception as exc:  # noqa: BLE001
            print(f"[cmcc-login-service] POST failed: {exc!r}", file=sys.stderr)
            self._send_error_json(ServiceError(500, "Internal Server Error"))

    def log_message(self, fmt: str, *args: Any) -> None:
        safe_path = urllib.parse.urlsplit(self.path).path
        sys.stderr.write(f"{self.address_string()} - {self.command} {safe_path}\n")


def re_fullmatch_flow_id(value: str) -> bool:
    return re.fullmatch(FLOW_ID_RE, value) is not None


class IPv6DualStackServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class IPv4Server(ThreadingHTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True
    allow_reuse_address = True


def create_server(host: str, port: int, config: AppConfig) -> ThreadingHTTPServer:
    address = ipaddress.ip_address(host)
    server_class = IPv6DualStackServer if address.version == 6 else IPv4Server
    server = server_class((host, port), Handler)
    server.app_config = config  # type: ignore[attr-defined]
    server.flow_store = FlowStore(  # type: ignore[attr-defined]
        config.flow_ttl, config.allow_non_global_observed_ip
    )
    return server


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ipv6", default=os.environ.get("CMCC_IPV6"), help="直连模式固定 IPv6"
    )
    parser.add_argument(
        "--webhook-token",
        default=os.environ.get("WEBHOOK_SITE_TOKEN"),
        help="启用 Webhook flow 模式的 Webhook.site UUID",
    )
    parser.add_argument(
        "--flow-ttl",
        type=int,
        default=int(os.environ.get("CMCC_FLOW_TTL", "120")),
        help="flow 有效期秒数，30..600，默认 120",
    )
    parser.add_argument(
        "--listen-host",
        default=os.environ.get("LISTEN_HOST", "::"),
        help="监听 IP，默认 ::；反代后可用 127.0.0.1 或 0.0.0.0",
    )
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("PORT", "8080"))
    )
    parser.add_argument(
        "--allow-non-global-observed-ip", action="store_true", help="仅供本地测试"
    )
    parser.add_argument(
        "--app-config",
        default=os.environ.get("CMCC_APP_CONFIG"),
        help="从 JSON 或 key=value 文件读取 appId/appKey/appPackage/appSign 覆盖值",
    )
    return parser.parse_args(argv)


def make_config(args: argparse.Namespace) -> AppConfig:
    forced_ipv6 = None
    if args.ipv6:
        forced_ipv6 = validate_observed_ipv6(args.ipv6, allow_non_global=True)
    webhook_token = validate_webhook_token(args.webhook_token) if args.webhook_token else None
    if webhook_token and forced_ipv6:
        raise ValueError("--webhook-token 与 --ipv6 是互斥模式")
    if not 30 <= args.flow_ttl <= 600:
        raise ValueError("--flow-ttl 必须在 30..600 秒之间")
    if not 1 <= args.port <= 65535:
        raise ValueError("--port 必须在 1..65535 之间")
    ipaddress.ip_address(args.listen_host)
    return AppConfig(
        forced_ipv6=forced_ipv6,
        webhook_token=webhook_token,
        flow_ttl=args.flow_ttl,
        allow_non_global_observed_ip=args.allow_non_global_observed_ip,
    )


def main() -> int:
    args = parse_args()
    try:
        builder.apply_app_config(builder.load_app_config(args.app_config))
        config = make_config(args)
        server = create_server(args.listen_host, args.port, config)
    except (OSError, ValueError, ServiceError, FileNotFoundError) as exc:
        print(f"[cmcc-login-service] 启动失败：{exc}", file=sys.stderr)
        return 2

    mode = "webhook flow" if config.webhook_token else "direct IPv6"
    print(
        f"[cmcc-login-service] listening on {args.listen_host}:{args.port} "
        f"({mode}, Ctrl-C 退出)"
    )
    app_cfg = builder.get_app_config()
    print(
        f"  appId={app_cfg['appId']} appPackage={app_cfg['appPackage']}"
        f" appSign={app_cfg['appSign']} (appKey 已加载)"
    )
    if config.webhook_token:
        print(f"  Webhook.site token: {config.webhook_token}")
    elif config.forced_ipv6:
        print(f"  固定 IPv6: {config.forced_ipv6}")
    print("  健康检查: /healthz；查看源 IP: /whoami")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[cmcc-login-service] stopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
