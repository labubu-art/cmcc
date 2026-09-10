#!/usr/bin/env python3
"""Monitor Webhook.site Host/IP observations and optionally forward flows."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

DEFAULT_VIEW_URL = (
    "https://webhook.site/#!/view/b709614b-90a0-43f1-8c3e-9b07eed36570"
)
API_ROOT = "https://webhook.site"
API_HOST = "webhook.site"
STATE_VERSION = 1
MAX_SAVED_IDS = 10_000
MAX_LOG_LINE_CHARS = 16_384
MAX_LOG_STRING_CHARS = 2_048
TRANSIENT_HTTP_STATUS = {408, 425, 429, 500, 502, 503, 504}
DEFAULT_INTERVAL = 0.6
DEFAULT_RECONCILE_INTERVAL = 3.0
MIN_INTERVAL = 0.55
SENSITIVE_LOG_KEY = re.compile(
    r"(?:^|[-_])(authorization|cookie|set-cookie|api-key|token|secret|session|password)(?:$|[-_])",
    re.IGNORECASE,
)


class MonitorError(RuntimeError):
    """A user-actionable monitor error."""


class TransientMonitorError(MonitorError):
    """A temporary error that may succeed when retried."""


class FatalMonitorError(MonitorError):
    """A configuration/authentication error that must stop the monitor."""


@dataclass(frozen=True)
class Page:
    records: list[dict[str, Any]]
    is_last_page: bool


def parse_token(value: str) -> str:
    """Extract and validate a Webhook.site UUID from a UUID or URL."""
    candidate = value.strip()
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        if parsed.hostname is None or not (
            parsed.hostname == "webhook.site"
            or parsed.hostname.endswith(".webhook.site")
        ):
            raise MonitorError("target 必须是 webhook.site URL 或 UUID")
        fragment_match = re.search(
            r"(?:^|/)view/([0-9a-fA-F-]{36})(?:/|$)", parsed.fragment
        )
        path_match = re.search(r"/([0-9a-fA-F-]{36})(?:/|$)", parsed.path)
        if fragment_match:
            candidate = fragment_match.group(1)
        elif path_match:
            candidate = path_match.group(1)
        else:
            subdomain = parsed.hostname.removesuffix(".webhook.site")
            candidate = subdomain if subdomain != "webhook.site" else ""

    try:
        return str(uuid.UUID(candidate))
    except (ValueError, AttributeError) as exc:
        raise MonitorError("无法从 target 提取合法的 Webhook.site UUID") from exc


def first_header(headers: Any, name: str) -> str | None:
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).casefold() != name.casefold():
            continue
        if isinstance(value, list):
            value = value[0] if value else None
        if value is None:
            return None
        return str(value).strip() or None
    return None


def hostname_from_authority(authority: str) -> str | None:
    authority = authority.strip()
    if not authority:
        return None
    try:
        parsed = urllib.parse.urlsplit("//" + authority)
        host = parsed.hostname
    except ValueError:
        host = None
    return host.rstrip(".").casefold() if host else None


def extract_host(record: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Return Host value, normalized hostname, and source."""
    host_header = first_header(record.get("headers"), "host")
    if host_header:
        return host_header, hostname_from_authority(host_header), "header"
    url = record.get("url")
    if isinstance(url, str):
        try:
            parsed = urllib.parse.urlsplit(url)
            hostname = parsed.hostname
            if hostname is None:
                return None, None, None
            authority = f"[{hostname}]" if ":" in hostname else hostname
            if parsed.port is not None:
                authority += f":{parsed.port}"
            return authority, hostname.rstrip(".").casefold(), "url"
        except ValueError:
            pass
    return None, None, None


def is_https_request(record: dict[str, Any]) -> bool:
    url = record.get("url")
    if not isinstance(url, str):
        return False
    try:
        return urllib.parse.urlsplit(url).scheme.casefold() == "https"
    except ValueError:
        return False


def query_value(record: dict[str, Any], name: str) -> str | None:
    query = record.get("query")
    if isinstance(query, dict):
        value = query.get(name)
        if isinstance(value, list):
            value = value[0] if value else None
        if value is not None and str(value).strip():
            return str(value).strip()
    url = record.get("url")
    if isinstance(url, str):
        try:
            parsed_qs = urllib.parse.parse_qs(
                urllib.parse.urlsplit(url).query, keep_blank_values=False
            )
        except ValueError:
            return None
        values = parsed_qs.get(name)
        if values:
            candidate = values[0].strip()
            if candidate:
                return candidate
    return None


def observed_ipv6(record: dict[str, Any]) -> str:
    value = str(record.get("ip") or "").split("%", 1)[0].strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise MonitorError("Webhook.site 记录缺少合法的顶层 ip") from exc
    if not isinstance(address, ipaddress.IPv6Address) or address.ipv4_mapped is not None:
        raise MonitorError(f"Webhook.site 观测地址不是原生 IPv6：{value or 'empty'}")
    return address.compressed


def terminal_safe(value: str, limit: int = 1024) -> str:
    value = value[:limit]
    return "".join(
        char if ord(char) >= 32 and ord(char) != 127 else f"\\x{ord(char):02x}"
        for char in value
    )


def sanitize_log_value(value: Any, key: str = "", depth: int = 0) -> Any:
    """Return a bounded, redacted copy suitable for diagnostic logs."""
    if key and SENSITIVE_LOG_KEY.search(key):
        return "[REDACTED]"
    if key.casefold() == "url" and isinstance(value, str):
        try:
            parsed = urllib.parse.urlsplit(value)
            value = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, "", "")
            )
        except ValueError:
            return "[invalid URL]"
    if depth >= 8:
        return "[MAX_DEPTH]"
    if isinstance(value, dict):
        return {
            str(item_key): sanitize_log_value(item_value, str(item_key), depth + 1)
            for item_key, item_value in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [sanitize_log_value(item, key, depth + 1) for item in value[:100]]
    if isinstance(value, str) and len(value) > MAX_LOG_STRING_CHARS:
        return value[:MAX_LOG_STRING_CHARS] + f"...[truncated {len(value) - MAX_LOG_STRING_CHARS} chars]"
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)[:MAX_LOG_STRING_CHARS]


def request_log_summary(record: dict[str, Any], source: str) -> dict[str, Any]:
    host, hostname, host_source = extract_host(record)
    raw_url = record.get("url")
    safe_url = None
    if isinstance(raw_url, str):
        try:
            parsed = urllib.parse.urlsplit(raw_url)
            safe_url = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, "", "")
            )
        except ValueError:
            safe_url = "[invalid URL]"
    query = record.get("query")
    query_keys = sorted(str(key) for key in query) if isinstance(query, dict) else []
    return {
        "event": "webhook.received",
        "source": source,
        "uuid": record.get("uuid"),
        "created_at": record.get("created_at"),
        "type": record.get("type"),
        "method": record.get("method"),
        "ip": record.get("ip"),
        "host": host,
        "hostname": hostname,
        "host_source": host_source,
        "url": safe_url,
        "flow_id": query_value(record, "flow_id"),
        "query_keys": query_keys,
        "size": record.get("size"),
    }


def log_received_record(record: dict[str, Any], mode: str, source: str) -> None:
    if mode == "off":
        return
    payload = request_log_summary(record, source)
    if mode == "full":
        payload["record"] = sanitize_log_value(record)
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(line) > MAX_LOG_LINE_CHARS:
        payload["record"] = {
            "truncated": True,
            "available_keys": sorted(str(key) for key in record),
        }
        line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    print(f"[webhook.received] {line}", file=sys.stderr, flush=True)


class WebhookSiteClient:
    def __init__(self, token: str, timeout: float) -> None:
        self.token = token
        self.timeout = timeout
        self._connection: http.client.HTTPSConnection | None = None

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _get_json(self, path: str, *, not_found_is_none: bool = False) -> Any:
        headers = {
            "Accept": "application/json",
            "User-Agent": "traex-webhook-site-monitor/0.3.0",
        }

        for attempt in range(2):
            if self._connection is None:
                self._connection = http.client.HTTPSConnection(
                    API_HOST, timeout=self.timeout
                )
            try:
                self._connection.request("GET", path, headers=headers)
                response = self._connection.getresponse()
                raw = response.read()
            except (
                http.client.HTTPException,
                ConnectionError,
                TimeoutError,
                OSError,
            ) as exc:
                self.close()
                if attempt == 0:
                    continue
                raise TransientMonitorError(f"连接 Webhook.site 失败：{exc}") from exc

            if response.status == 404 and not_found_is_none:
                return None
            if response.status in TRANSIENT_HTTP_STATUS:
                self.close()
                raise TransientMonitorError(
                    f"Webhook.site 暂时不可用（HTTP {response.status}）"
                )
            if response.status == 404:
                raise FatalMonitorError(
                    "Webhook.site token 不存在或已过期（HTTP 404）"
                )
            if not 200 <= response.status < 300:
                raise MonitorError(f"Webhook.site API 返回 HTTP {response.status}")
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise MonitorError("Webhook.site API 返回了无效 JSON") from exc
        raise AssertionError("unreachable")

    def fetch_page(self, page_number: int) -> Page:
        query = urllib.parse.urlencode(
            {"sorting": "newest", "per_page": 100, "page": page_number}
        )
        path = f"/token/{self.token}/requests?{query}"
        payload = self._get_json(path)

        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise MonitorError("Webhook.site API 响应结构不符合预期")
        records = [item for item in payload["data"] if isinstance(item, dict)]
        return Page(records=records, is_last_page=bool(payload.get("is_last_page")))

    def fetch_latest(self) -> dict[str, Any] | None:
        payload = self._get_json(
            f"/token/{self.token}/request/latest", not_found_is_none=True
        )
        if payload is None:
            return None
        if not isinstance(payload, dict):
            raise MonitorError("Webhook.site latest 响应结构不符合预期")
        return payload


def collect_unseen(
    fetch_page: Callable[[int], Page],
    seen: set[str],
    max_pages: int,
) -> list[dict[str, Any]]:
    """Collect unseen records, returned in chronological order."""
    unseen_newest_first: list[dict[str, Any]] = []
    collected_ids: set[str] = set()
    found_anchor = False
    reached_last = False

    for page_number in range(1, max_pages + 1):
        page = fetch_page(page_number)
        for record in page.records:
            request_id = str(record.get("uuid") or "")
            if not request_id:
                continue
            if request_id in seen:
                found_anchor = True
                break
            if request_id in collected_ids:
                continue
            collected_ids.add(request_id)
            unseen_newest_first.append(record)
        if found_anchor or page.is_last_page:
            reached_last = page.is_last_page
            break

    if not found_anchor and not reached_last:
        if seen:
            raise MonitorError(
                f"连续 {max_pages} 页未找到上次锚点；为避免漏报，已停止。"
                "请提高 --max-pages 或确认后建立新基线。"
            )
        raise MonitorError(
            f"首次扫描超过 {max_pages} 页；为避免漏报，已停止。请提高 --max-pages。"
        )
    unseen_newest_first.reverse()
    return unseen_newest_first


def load_state(path: Path, token: str) -> tuple[bool, list[str]]:
    if not path.exists():
        return False, []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MonitorError(f"无法读取状态文件 {path}: {exc}") from exc
    if payload.get("version") != STATE_VERSION or payload.get("token") != token:
        raise MonitorError(f"状态文件 {path} 的版本或 token 不匹配")
    ids = payload.get("seen_request_ids")
    if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
        raise MonitorError(f"状态文件 {path} 的 seen_request_ids 无效")
    return True, ids[-MAX_SAVED_IDS:]


def save_state(path: Path, token: str, ids: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    saved_ids = list(ids)[-MAX_SAVED_IDS:]
    payload = {
        "version": STATE_VERSION,
        "token": token,
        "seen_request_ids": saved_ids,
    }
    temp_path = path.with_name(path.name + f".tmp-{os.getpid()}")
    try:
        temp_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temp_path, path)
    except OSError as exc:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise MonitorError(f"无法写入状态文件 {path}: {exc}") from exc


def emit_record(record: dict[str, Any], jsonl: bool) -> None:
    host, hostname, host_source = extract_host(record)
    if not host:
        request_id = terminal_safe(str(record.get("uuid") or "unknown"))
        print(f"警告：请求 {request_id} 没有可提取的 Host", file=sys.stderr)
        return
    if jsonl:
        url = record.get("url")
        scheme = None
        if isinstance(url, str):
            try:
                scheme = urllib.parse.urlsplit(url).scheme or None
            except ValueError:
                pass
        output = {
            "host": host,
            "hostname": hostname,
            "host_source": host_source,
            "scheme": scheme,
            "uuid": record.get("uuid"),
            "method": record.get("method"),
            "created_at": record.get("created_at"),
        }
        print(json.dumps(output, ensure_ascii=False), flush=True)
    else:
        print(terminal_safe(host), flush=True)


def process_record(
    record: dict[str, Any],
    args: argparse.Namespace,
    forward_base: str | None,
    source: str = "api",
) -> None:
    log_received_record(record, getattr(args, "record_log", "summary"), source)
    if not (args.allow_http or is_https_request(record)):
        return
    if forward_base:
        if record.get("type") not in {None, "web"}:
            return
        if not query_value(record, "flow_id"):
            return
        try:
            path = urllib.parse.urlsplit(str(record.get("url") or "")).path
        except ValueError:
            return
        if not path.endswith("/cmcc-ip.gif"):
            return
        if forward_observation(record, forward_base, args.timeout):
            print(
                json.dumps(
                    {
                        "flow_id": query_value(record, "flow_id"),
                        "observed_ip": observed_ipv6(record),
                        "forwarded": True,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        return
    emit_record(record, args.jsonl)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def validate_forward_base(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise MonitorError("--forward-base-url 必须是有效 http(s) origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise MonitorError("--forward-base-url 不能包含凭据、query 或 fragment")
    if parsed.path not in {"", "/"}:
        raise MonitorError("--forward-base-url 必须是 origin，不能包含路径")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def forward_observation(
    record: dict[str, Any], base_url: str, timeout: float
) -> bool:
    flow_id = query_value(record, "flow_id")
    if not flow_id:
        return False
    try:
        parsed_id = uuid.UUID(flow_id)
    except ValueError as exc:
        raise MonitorError("webhook 请求中的 flow_id 不是合法 UUID") from exc
    if parsed_id.version != 4 or str(parsed_id) != flow_id.casefold():
        raise MonitorError("webhook 请求中的 flow_id 必须是规范 UUIDv4")

    request_id = str(record.get("uuid") or "")
    try:
        request_id = str(uuid.UUID(request_id))
    except ValueError as exc:
        raise MonitorError("webhook 请求 UUID 无效") from exc
    ip = observed_ipv6(record)
    endpoint = f"{base_url}/api/flows/{flow_id}/observation"
    body = json.dumps(
        {"observed_ip": ip, "webhook_request_id": request_id},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "traex-webhook-site-monitor/0.3.0",
        },
    )
    opener = urllib.request.build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                raise MonitorError(f"flow 回调返回 HTTP {response.status}")
            response.read(4096)
    except urllib.error.HTTPError as exc:
        if exc.code in TRANSIENT_HTTP_STATUS:
            raise TransientMonitorError(f"flow 回调暂时失败（HTTP {exc.code}）") from exc
        raise MonitorError(f"flow 回调被拒绝（HTTP {exc.code}）") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TransientMonitorError(f"连接 flow 服务失败：{exc}") from exc
    return True


def open_chrome(view_url: str) -> None:
    if sys.platform == "darwin":
        command = ["/usr/bin/open", "-a", "Google Chrome", view_url]
    elif sys.platform.startswith("linux"):
        command = ["google-chrome", view_url]
    else:
        raise MonitorError("--open-chrome 当前只支持 macOS 和 Linux")
    try:
        subprocess.run(
            command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise MonitorError(f"无法打开 Google Chrome：{exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="监控 Webhook.site 新增 HTTPS 请求并输出 Host"
    )
    parser.add_argument("--target", default=DEFAULT_VIEW_URL, help="view URL、接收 URL 或 UUID")
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help="latest 快路径轮询间隔秒数（默认 0.6）",
    )
    parser.add_argument(
        "--reconcile-interval",
        type=float,
        default=DEFAULT_RECONCILE_INTERVAL,
        help="列表补偿间隔秒数（默认 3）",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="单次 API 超时秒数")
    parser.add_argument("--max-pages", type=int, default=20, help="每轮最多读取页数")
    parser.add_argument("--state-file", type=Path, help="可选的持久化去重状态文件")
    parser.add_argument("--include-existing", action="store_true", help="输出启动前已有请求")
    parser.add_argument("--allow-http", action="store_true", help="同时输出非 HTTPS 请求")
    parser.add_argument("--jsonl", action="store_true", help="输出结构化 JSON Lines")
    parser.add_argument(
        "--record-log",
        choices=("off", "summary", "full"),
        default="summary",
        help="stderr 请求日志级别：off、summary（默认）或经脱敏限长的 full",
    )
    parser.add_argument("--once", action="store_true", help="完成初始化/单轮检查后退出")
    parser.add_argument("--open-chrome", action="store_true", help="启动时在 Chrome 打开页面")
    parser.add_argument(
        "--forward-base-url", help="把带 flow_id 的记录顶层 ip 回传到此 CMCC 服务 origin"
    )
    return parser


def run(args: argparse.Namespace) -> int:
    if args.interval < MIN_INTERVAL:
        raise MonitorError(
            f"--interval 不能小于 {MIN_INTERVAL:g} 秒，以免超过 API 限流"
        )
    if args.reconcile_interval < args.interval:
        raise MonitorError(
            "--reconcile-interval 不能小于 --interval"
        )
    estimated_requests_per_minute = 60.0 / args.interval
    if estimated_requests_per_minute > 110:
        raise MonitorError(
            "轮询配置预计超过安全 API 预算（110 次/分钟），请增大间隔"
        )
    if args.timeout <= 0 or args.max_pages <= 0:
        raise MonitorError("--timeout 和 --max-pages 必须大于 0")

    token = parse_token(args.target)
    forward_base = None
    if args.forward_base_url:
        forward_base = validate_forward_base(args.forward_base_url)
    view_url = f"https://webhook.site/#!/view/{token}"
    if args.open_chrome:
        open_chrome(view_url)

    client = WebhookSiteClient(token, args.timeout)
    if args.state_file:
        state_initialized, seen_order = load_state(args.state_file, token)
    else:
        state_initialized, seen_order = False, []
    seen = set(seen_order)
    fast_seen: set[str] = set()

    if not state_initialized:
        if args.include_existing:
            initial = collect_unseen(client.fetch_page, set(), args.max_pages)
            for record in initial:
                request_id = str(record.get("uuid") or "")
                try:
                    process_record(record, args, forward_base, "initial")
                except TransientMonitorError:
                    if args.state_file:
                        save_state(args.state_file, token, seen_order)
                    raise
                except FatalMonitorError:
                    raise
                except MonitorError as exc:
                    print(f"跳过请求 {terminal_safe(request_id)}：{exc}", file=sys.stderr)
                if request_id:
                    seen.add(request_id)
                    seen_order.append(request_id)
        else:
            first_page = client.fetch_page(1)
            for record in reversed(first_page.records):
                request_id = str(record.get("uuid") or "")
                if request_id:
                    seen.add(request_id)
                    seen_order.append(request_id)
        if args.state_file:
            save_state(args.state_file, token, seen_order)
        print(
            f"正在监控 {view_url}；基线 {len(seen)} 条，"
            f"latest 间隔 {args.interval:g} 秒，列表补偿 {args.reconcile_interval:g} 秒",
            file=sys.stderr,
            flush=True,
        )
        if args.once:
            return 0

    stopping = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    failures = 0
    next_poll = time.monotonic()
    next_reconcile = next_poll if args.once else next_poll + args.reconcile_interval

    try:
        while not stopping:
            if not args.once:
                wait = max(0.0, next_poll - time.monotonic())
                if wait:
                    time.sleep(wait)
                if stopping:
                    break
            poll_started = time.monotonic()
            try:
                failures = 0
                now = time.monotonic()
                if args.once or now >= next_reconcile:
                    records = collect_unseen(client.fetch_page, seen, args.max_pages)
                    reconciled_ids: list[str] = []
                    for record in records:
                        request_id = str(record.get("uuid") or "")
                        if request_id not in fast_seen:
                            try:
                                process_record(record, args, forward_base, "reconcile")
                            except MonitorError as exc:
                                if isinstance(exc, (TransientMonitorError, FatalMonitorError)):
                                    raise
                                print(
                                    f"跳过请求 {terminal_safe(request_id)}：{exc}",
                                    file=sys.stderr,
                                )
                        if request_id:
                            seen.add(request_id)
                            seen_order.append(request_id)
                            reconciled_ids.append(request_id)
                    fast_seen.difference_update(reconciled_ids)
                    if records:
                        seen_order = seen_order[-MAX_SAVED_IDS:]
                        seen = set(seen_order)
                        if args.state_file:
                            save_state(args.state_file, token, seen_order)
                    next_reconcile = time.monotonic() + args.reconcile_interval
                else:
                    latest = client.fetch_latest()
                    if latest:
                        request_id = str(latest.get("uuid") or "")
                        if (
                            request_id
                            and request_id not in seen
                            and request_id not in fast_seen
                        ):
                            try:
                                process_record(latest, args, forward_base, "latest")
                            except MonitorError as exc:
                                if isinstance(
                                    exc, (TransientMonitorError, FatalMonitorError)
                                ):
                                    raise
                                print(
                                    f"跳过请求 {terminal_safe(request_id)}：{exc}",
                                    file=sys.stderr,
                                )
                            fast_seen.add(request_id)
                            next_reconcile = min(
                                next_reconcile, time.monotonic() + args.interval
                            )
                if args.once:
                    return 0
            except TransientMonitorError as exc:
                failures += 1
                if args.once:
                    raise
                delay = min(60.0, args.interval * (2 ** min(failures, 5)))
                print(f"{exc}；{delay:g} 秒后重试", file=sys.stderr, flush=True)
                time.sleep(delay)
                client.close()
                next_reconcile = time.monotonic()
            next_poll = max(next_poll + args.interval, poll_started + args.interval)
    finally:
        client.close()

    print("监控已停止", file=sys.stderr)
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run(args)
    except MonitorError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("监控已停止", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
