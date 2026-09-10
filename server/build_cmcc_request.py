#!/usr/bin/env python3
"""Build a CMCC unisdk request body from hardcoded plaintext fields.

All values below come from the sample captured in
captured_requests/gateway_20260828_150152.json. To reproduce that exact
request, run the script with no arguments.

Usage:
    tools/.venv/bin/python tools/build_cmcc_request.py
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_KEY_B64 = "NGJhOTdmMDYtMmVjNi00Nw=="
AES_IV_B64 = "lIbiN+s25HWPvFlQMXym4A=="

APP_CONFIG_KEYS = ("appId", "appKey", "appPackage", "appSign")
DEFAULT_APP_CONFIG: dict[str, str] = {
    "appId": "300011971960",
    # 来源: cmcc.properties -> BuildConfig.CMCC_APP_KEY。改这个值也必须重算 sign。
    "appKey": "92F73C02D42B096941B405D9AB3E564C",
    "appPackage": "com.ss.android.lark",
    "appSign": "C7D6BEA9B9F7EA2938B7ED89517A198C",
}


def load_app_config(path: str | os.PathLike[str] | None) -> dict[str, str]:
    """加载 appId/appKey/appPackage/appSign 覆盖值。

    支持 JSON 文件、`key=value` 行格式（Java properties 子集，忽略 `#` 注释），
    以及键名的大小写/下划线变体（例如 `APP_ID`、`app_key`）。未在文件里出现的
    键回退到 `DEFAULT_APP_CONFIG`。
    """
    config = dict(DEFAULT_APP_CONFIG)
    if not path:
        return config
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"CMCC app config 不存在：{p}")
    text = p.read_text(encoding="utf-8")
    parsed: dict[str, str]
    try:
        loaded = json.loads(text)
        if not isinstance(loaded, dict):
            raise ValueError("配置文件 JSON 顶层必须是对象")
        parsed = {str(k): str(v) for k, v in loaded.items()}
    except json.JSONDecodeError:
        parsed = {}
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if "=" not in line:
                raise ValueError(
                    f"配置文件第 {lineno} 行缺少 '='：{raw!r}"
                )
            key, _, value = line.partition("=")
            parsed[key.strip()] = value.strip()

    def canonical(key: str) -> str:
        return key.replace("_", "").replace("-", "").casefold()

    canon_lookup = {canonical(k): v for k, v in parsed.items()}
    for target in APP_CONFIG_KEYS:
        override = canon_lookup.get(canonical(target))
        if override is not None:
            if not override:
                raise ValueError(f"配置文件里 {target} 不能为空字符串")
            config[target] = override
    return config


# 与运行时读取到的 app 配置保持一致的模块级缓存，供 CLI 和服务端共同使用。
_APP_CONFIG: dict[str, str] = dict(DEFAULT_APP_CONFIG)


def apply_app_config(config: dict[str, str]) -> None:
    """把加载好的 app 配置绑定为模块级默认值。"""
    global _APP_CONFIG
    missing = [key for key in APP_CONFIG_KEYS if not config.get(key)]
    if missing:
        raise ValueError(f"app 配置缺少字段：{', '.join(missing)}")
    _APP_CONFIG = {key: config[key] for key in APP_CONFIG_KEYS}


def get_app_config() -> dict[str, str]:
    return dict(_APP_CONFIG)


URL = "https://rcs.cmpassport.com/unisdk/rs/scripAndTokenForHttps"
HEADERS = {
    "appid": DEFAULT_APP_CONFIG["appId"],
    "CMCC-EncryptType": "STD",
    "connection": "Keep-Alive",
    "Content-Type": "application/json",
    "defendEOF": "1",
    "interfaceVersion": "3.0",
    "sdkVersion": "quick_login_android_9.5.5.1",
    "traceId": "1bd1c1a8c5214d1e889f58f965c32830",
}

RSA_1024_PUBLIC_KEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNFGdEpQ1d8cPqekvvEDQyBGnI"
    "KwvjX9o3OmnnqWMGbIiFYIpc21QeG7aqizuWdXlgS5M9rstDfHQfG/AaPElJ7Yix"
    "BCau4hdVwFpRmb9NIuqavDeHKP9BKPZ01Ra5/666NGKBqmkRRer3lBCe6EKNUc2U"
    "/DZg6U/Q3CTPiORt/wIDAQAB"
)

# ---------------------------------------------------------------------------
# plaintextParams 是把下面这个 dict 按 PLAINTEXT_FIELD_ORDER 顺序取值、用 '&'
# 连接得到的字符串，对应 CmccDirectLoginClient.kt 里 RequestParameters.plaintext()。
#
# 字段来源说明:
#   ver           SDK 协议版本，写死 "1.0"（CmccDirectLoginClient.kt: RequestParameters.ver 默认值）
#   sdkVer        SDK 版本号常量，SDK_VERSION = "quick_login_android_9.5.5.1"
#   appId         中国移动一键登录 appId，来自 cmcc.properties -> BuildConfig.CMCC_APP_ID
#   imsi          明文 IMSI，SDK 侧固定为空串，实际由网关侧通过蜂窝会话解析
#   operatorType  运营商类型：TelephonyManager.simOperator + detectOperatorType()
#                 移动=1(此次样本)、联通=2、电信=3、未知=0
#   networkType   网络类型，配合 requireCellularOnly，蜂窝下固定 "1"
#   mobileBrand   URLEncoder.encode(Build.BRAND, "UTF-8")，Pixel 6 上是 "google"
#   mobileModel   URLEncoder.encode(Build.MODEL, "UTF-8")，空格会被编码成 '+'，故 "Pixel+6"
#   mobileSystem  URLEncoder.encode("android" + Build.VERSION.RELEASE)，此机为 "android15"
#   clientType    客户端类型，Android 固定 "0"
#   interfaceVer  接口版本 "3.0"，跟 header interfaceVersion 一致
#   expandParams  扩展字段，SDK 侧固定空串
#   messageId     每次请求随机的 UUID.randomUUID().toString().replace("-","")
#   timestamp     SimpleDateFormat("yyyyMMddHHmmssSSS", Locale.US).format(new Date())
#   subImsi       副卡 IMSI，SDK 侧固定空串
#   sign          MD5 十六进制小写，参与哈希的字段顺序见 RequestParameters.withSignature()：
#                 sdkVer + appId + imsi + operatorType + networkType + mobileBrand +
#                 mobileModel + mobileSystem + clientType + messageId + timestamp +
#                 appKey + subImsi + appPackage + appSign + ipv4List + ipv6List +
#                 sdkType + tempPdr + scrip + userCapaid + funcType + socketIp
#                 注：sign 里用到的 appKey (BuildConfig.CMCC_APP_KEY) 本身不进入 plaintext
#   appPackage    调用方包名，来自 cmcc.properties -> BuildConfig.CMCC_APP_PACKAGE
#   appSign       调用方签名 MD5（32 hex，大写），来自 cmcc.properties -> BuildConfig.CMCC_APP_SIGN
#   boundid       固定占位空字段，plaintext() 里第 19 位显式写为 ""
#   ipv4List      非 WLAN 接口的 IPv4 地址列表，逗号分隔；单卡场景通常只有 rmnet 上的一个
#   ipv6List      非 WLAN 接口的 IPv6 地址列表，逗号分隔
#   sdkType       SDK 类型编号 "002"
#   tempPdr       持久化 AID：首次生成 "%" + UUID32，之后存 SharedPreferences("cmcc_direct_login","AID")
#   scrip         预取号 scrip，一次性 token 前置流程未走到时为空
#   userCapaid    能力位 "200"（授权码模式）
#   funcType      功能类型 "authz"
#   socketIp      TLS socket 建立后本地端 IP，从 RecordingSslSocketFactory 记录，即蜂窝出栈 IP
# ---------------------------------------------------------------------------
PLAINTEXT_FIELDS = {
    "ver":          "1.0",
    "sdkVer":       "quick_login_android_9.5.5.1",
    "appId":        "300011971960",
    "imsi":         "",
    "operatorType": "1",
    "networkType":  "1",
    "mobileBrand":  "google",
    "mobileModel":  "Pixel+6",
    "mobileSystem": "android15",
    "clientType":   "0",
    "interfaceVer": "3.0",
    "expandParams": "",
    "messageId":    "4db017068b544886a45eccb3ae9e67f5",
    "timestamp":    "20260828150152372",
    "subImsi":      "",
    # sign 会在运行时由 compute_sign() 根据其它字段 + APP_KEY 重算，这里的占位值不会被使用。
    "sign":         "",
    "appPackage":   "com.ss.android.lark",
    "appSign":      "C7D6BEA9B9F7EA2938B7ED89517A198C",
    "boundid":      "",
    "ipv4List":     "10.146.13.39",
    "ipv6List":     "2409:8929:e85:433d:e4db:d1ff:fe0a:aebe",
    "sdkType":      "002",
    "tempPdr":      "%645ae41398464d4b810c94c2ad898538",
    "scrip":        "",
    "userCapaid":   "200",
    "funcType":     "authz",
    "socketIp":     "2409:8929:e85:433d:e4db:d1ff:fe0a:aebe",
}

PLAINTEXT_FIELD_ORDER = [
    "ver", "sdkVer", "appId", "imsi", "operatorType", "networkType",
    "mobileBrand", "mobileModel", "mobileSystem", "clientType",
    "interfaceVer", "expandParams", "messageId", "timestamp", "subImsi",
    "sign", "appPackage", "appSign", "boundid", "ipv4List", "ipv6List",
    "sdkType", "tempPdr", "scrip", "userCapaid", "funcType", "socketIp",
]


# CmccDirectLoginClient.kt: RequestParameters.withSignature() 里参与 MD5 的字段顺序。
# 注意 appKey 是从外部注入（不放进 PLAINTEXT_FIELDS，改动 APP_KEY 同样需要重算 sign）。
SIGN_FIELD_ORDER = [
    "sdkVer", "appId", "imsi", "operatorType", "networkType",
    "mobileBrand", "mobileModel", "mobileSystem", "clientType",
    "messageId", "timestamp",
    # <appKey> 在这里插入
    "subImsi", "appPackage", "appSign",
    "ipv4List", "ipv6List", "sdkType", "tempPdr", "scrip",
    "userCapaid", "funcType", "socketIp",
]


def compute_sign(fields: dict[str, str], app_key: str) -> str:
    """按 CmccDirectLoginClient.kt 的顺序拼接后 MD5，输出十六进制小写。"""
    parts: list[str] = []
    for key in SIGN_FIELD_ORDER:
        parts.append(fields[key])
        if key == "timestamp":
            parts.append(app_key)
    digest = hashlib.md5("".join(parts).encode("utf-8")).hexdigest()
    return digest.lower()


def build_plaintext(fields: dict[str, str]) -> str:
    return "&".join(fields[k] for k in PLAINTEXT_FIELD_ORDER)


def android_b64(data: bytes) -> str:
    return base64.encodebytes(data).decode("ascii")


def rsa_encrypt_key(aes_key: bytes) -> str:
    pub = serialization.load_der_public_key(base64.b64decode(RSA_1024_PUBLIC_KEY_B64))
    # 实机验证：Pixel 6 / Android 15 的 Conscrypt 对
    # "RSA/ECB/OAEPWithSHA256AndMGF1Padding" 的 MGF1 也走 SHA-256，
    # 而不是常见 JCA 语义里的 MGF1(SHA-1)。参见 tools/oaep_variants.py 与
    # DEBUG_OVERRIDE_ENCRYPTED 的 A/B 结果 (2026-08-28)。
    ct = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    return ct.hex().upper()


def aes_cbc_encrypt(plaintext: str, key: bytes, iv: bytes) -> str:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return android_b64(enc.update(padded) + enc.finalize())


def decrypt_result_data(
    ciphertext_b64: str, iv_b64: str | None = None, key_b64: str | None = None
) -> str:
    """AES-CBC 解密 resultData；IV/Key 缺省用会话默认。"""
    key = base64.b64decode(key_b64 or AES_KEY_B64)
    iv = base64.b64decode(iv_b64 or AES_IV_B64)
    ct = base64.b64decode(ciphertext_b64)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode(
        "utf-8", errors="replace"
    )


def shell_quote(v: str) -> str:
    return "'" + v.replace("'", "'\\''") + "'"


def now_timestamp() -> str:
    """SimpleDateFormat('yyyyMMddHHmmssSSS') 的等价实现。"""
    now = datetime.datetime.now()
    return now.strftime("%Y%m%d%H%M%S") + f"{now.microsecond // 1000:03d}"


def build_request_bundle(
    ipv6: str | None = None, *, refresh_runtime: bool = False
) -> dict[str, object]:
    """构造完整请求；服务端使用 refresh_runtime 为每个 flow 刷新时效字段。"""
    app = get_app_config()
    fields = dict(PLAINTEXT_FIELDS)
    fields["appId"] = app["appId"]
    fields["appPackage"] = app["appPackage"]
    fields["appSign"] = app["appSign"]
    if ipv6:
        fields["ipv6List"] = ipv6
        fields["socketIp"] = ipv6
    if refresh_runtime:
        fields["messageId"] = uuid.uuid4().hex
        fields["timestamp"] = now_timestamp()
    fields["sign"] = compute_sign(fields, app["appKey"])
    plaintext = build_plaintext(fields)

    aes_key = base64.b64decode(AES_KEY_B64)
    aes_iv = base64.b64decode(AES_IV_B64)
    body = {
        "encrypted": rsa_encrypt_key(aes_key),
        "encryptedIV": android_b64(aes_iv),
        "reqdata": aes_cbc_encrypt(plaintext, aes_key, aes_iv),
    }
    body_raw = json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    headers = dict(HEADERS)
    headers["appid"] = app["appId"]
    if refresh_runtime:
        headers["traceId"] = uuid.uuid4().hex

    curl_parts = ["curl", "-v", "-X", "POST"]
    for name, value in headers.items():
        curl_parts += ["-H", shell_quote(f"{name}: {value}")]
    curl_parts += ["--data-binary", shell_quote(body_raw), shell_quote(URL)]

    return {
        "url": URL,
        "method": "POST",
        "headers": headers,
        "sign": fields["sign"],
        "plaintextParams": plaintext,
        "body": body,
        "body_raw": body_raw,
        "curl": " ".join(curl_parts),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ipv6",
        help="覆盖 PLAINTEXT_FIELDS 中的 ipv6List 与 socketIp；同时把新的 body_raw 写回 cmcc-token-probe_index.html 里的 PREFILL 对象。",
    )
    parser.add_argument(
        "--app-config",
        default=os.environ.get("CMCC_APP_CONFIG"),
        help="从 JSON 或 key=value 文件读取 appId/appKey/appPackage/appSign 覆盖值",
    )
    args = parser.parse_args()

    apply_app_config(load_app_config(args.app_config))
    bundle = build_request_bundle(args.ipv6)
    print(json.dumps(bundle, ensure_ascii=False, indent=2))

    if args.ipv6:
        html_path = Path(__file__).with_name("cmcc-token-probe_index.html")
        if html_path.exists():
            html = html_path.read_text(encoding="utf-8")
            # PREFILL.body_raw 是一段 JSON 字符串字面量，需按 JS 语法转义后再替换。
            new_literal = json.dumps(bundle["body_raw"], ensure_ascii=False)
            pattern = re.compile(r'("body_raw"\s*:\s*)"(?:\\.|[^"\\])*"')
            new_html, n = pattern.subn(
                lambda m: m.group(1) + new_literal, html, count=1
            )
            if n == 0:
                print("warning: 未在 HTML 中找到 body_raw 字段，未替换。",
                      file=sys.stderr)
            else:
                html_path.write_text(new_html, encoding="utf-8")
                print(f"updated: {html_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
