"""内置安全工具（stdlib 实现，零外部依赖保证闭环可跑）。

仅做被动侦察与探测，不执行攻击动作；高危动作由外部工具 + 护栏承担。
"""
from __future__ import annotations

import ipaddress
import json
import socket
import urllib.parse
import urllib.request
from pathlib import Path


def _allow_http_url(url: str) -> str:
    """工具体内的 URL 边界校验（PolicyGate 闸门之外的第二道防线）。

    urlopen 原生支持 file:// 等危险 scheme，且不经过闸门的直接调用路径
    仍然可达本函数——因此这里必须自带同一条边界：仅 http(s) 协议；域名
    解析结果落在链路本地（云元数据 169.254.0.0/16）、组播或保留段一律拒绝。
    环回/私网是本工具的合法目标（操作员显式授权，默认白名单
    127.0.0.1/localhost，由 PolicyGate 在执行前机制性校验），不在此阻断。
    """
    parsed = urllib.parse.urlparse(str(url))
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL 协议不被允许: {parsed.scheme!r}（仅 http/https）")
    host = (parsed.hostname or "").strip()
    if not host:
        raise ValueError("URL 缺少主机名")
    for info in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise ValueError(f"目标解析到被禁止的地址: {ip}")
    return str(url)


def port_scan(host: str, ports: str = "80,443,8080,22,3306",
              timeout: float = 1.5) -> dict:
    """TCP 端口扫描（指定端口列表）。"""
    open_ports = []
    for p in (x.strip() for x in ports.split(",")):
        if not p.isdigit():
            continue
        port = int(p)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)
        finally:
            s.close()
    return {"host": host, "open_ports": open_ports}


def http_probe(url: str, timeout: float = 8.0) -> dict:
    """HTTP 探测：状态码/头/标题。"""
    try:
        req = urllib.request.Request(
            _allow_http_url(url),
            headers={"User-Agent": "XPentest/0.1 (authorized test)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            headers = {k: v for k, v in resp.headers.items()}
            return {"url": url, "status": resp.status,
                    "server": headers.get("Server", ""),
                    "headers": dict(list(headers.items())[:8]),
                    "title": _title(body)}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code,
                "server": exc.headers.get("Server", ""), "title": "",
                "note": f"HTTP {exc.code}"}
    except Exception as exc:
        return {"url": url, "error": str(exc)}


def _title(body: str) -> str:
    import re

    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return m.group(1).strip()[:80] if m else ""


def dns_lookup(domain: str) -> dict:
    """DNS 解析。"""
    try:
        return {"domain": domain, "ips": list(
            {a[4][0] for a in socket.getaddrinfo(domain, None)})}
    except socket.gaierror as exc:
        return {"domain": domain, "error": str(exc)}


def robots_fetch(base_url: str, timeout: float = 5.0) -> dict:
    """抓取 robots.txt（被动信息收集）。"""
    import urllib.error

    url = base_url.rstrip("/") + "/robots.txt"
    try:
        with urllib.request.urlopen(
                _allow_http_url(url), timeout=timeout) as resp:
            text = resp.read(2048).decode("utf-8", errors="replace")
        disallow = [ln.split(":", 1)[1].strip()
                    for ln in text.splitlines()
                    if ln.lower().startswith("disallow")]
        return {"url": url, "status": resp.status, "disallow": disallow}
    except Exception as exc:
        return {"url": url, "error": str(exc)}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随重定向：3xx 本身就是要取证的证据（跳转链、Location 值）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _clean_headers(headers, cookie: str = "") -> tuple[dict, list[str]]:
    """规整请求头：字段名/值逐条校验，返回 (干净的头, 问题列表)。

    三条边界（不是洁癖，是安全）：
    - **拒绝 CR/LF**：请求头注入（CRLF injection）是最经典的绕过面，值里带
      换行等于让调用方拼出额外请求；
    - 头名只允许 RFC 7230 的 tchar，值限长 2000、总数限 20；
    - 失败**逐条丢弃并报告**，不静默吞掉（调用方要能看出哪条没生效）。
    """
    import re

    token_re = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
    clean: dict[str, str] = {}
    problems: list[str] = []

    raw = headers
    if isinstance(raw, str):
        import json as _json

        try:
            raw = _json.loads(raw) if raw.strip() else {}
        except _json.JSONDecodeError as exc:
            return {}, [f"headers 不是合法 JSON: {exc}"]
    if raw is not None and not isinstance(raw, dict):
        return {}, ["headers 必须是对象（{名称: 值}）"]

    items = list((raw or {}).items())
    if cookie:
        items.append(("Cookie", str(cookie)))
    for name, value in items:
        key = str(name).strip()
        val = "" if value is None else str(value)
        if not token_re.match(key):
            problems.append(f"头名非法: {key!r}")
            continue
        if "\r" in val or "\n" in val:
            problems.append(f"头值含换行（请求头注入）已拒绝: {key}")
            continue
        if len(val) > 2000:
            problems.append(f"头值过长（>2000）: {key}")
            continue
        if len(clean) >= 20:
            problems.append("请求头超过 20 条，其余丢弃")
            break
        clean[key] = val
    return clean, problems


def _mask_headers(headers: dict) -> list[list[str]]:
    """证据里记录请求头时，对凭据类头脱敏（只留前 8 位与长度）。"""
    secret = {"cookie", "authorization", "x-api-key", "x-auth-token"}
    out = []
    for k, v in headers.items():
        if k.lower() in secret and len(v) > 8:
            out.append([k, f"{v[:8]}…（已脱敏，共 {len(v)} 字符）"])
        else:
            out.append([k, v])
    return out


def http_raw(url: str, method: str = "GET", body: str = "",
             headers=None, cookie: str = "",
             timeout: float = 10.0, max_body: int = 4000) -> dict:
    """HTTP 原始探测（本地直连）：状态行 + 完整响应头 + 正文片段 + 耗时。

    与 `http_probe` 的分工：那个只给**结论性字段**（状态码/标题/Server），
    这个给**原始证据**——2026-09-21 的 DSH 真机实测中，模型拒绝用内核工具、
    改用宿主 shell 的理由之一正是"`http_probe` 的固化输出给不了原始响应头与
    正文，做不了精细判读"（判 `Server`/`X-Powered-By` 是否真缺失、用
    `Content-Type` 甄别 SPA 兜底页、看 3xx 的 `Location`）。

    `headers` / `cookie`（2026-09-22 补）：支持带认证态的请求——需要登录的
    靶场（先 POST 登录拿 Set-Cookie，再把 cookie 带进后续请求）此前在核心里
    做不了。头值里的 CR/LF 一律拒绝（请求头注入），凭据类头在**返回的请求头
    记录里脱敏**（证据留痕但不落明文凭据）。

    三个刻意的行为：
    - **不跟随重定向**（3xx 原样返回，带 `location`）；
    - 4xx/5xx **不抛异常**，按响应返回（错误页正文同样是证据）；
    - 正文按 `max_body` 截断（默认 4000 字符，硬上限 20000），带 `truncated`
      标记——避免把上下文撑爆。

    边界与 `http_probe` 同源：仍走 `_allow_http_url`（仅 http/https、
    链路本地/组播/保留段拒绝）；目标白名单由 PolicyGate 在执行前裁决。
    """
    import time as _time
    import urllib.error

    method = (method or "GET").strip().upper()
    if method not in ("GET", "HEAD", "POST"):
        return {"url": url, "method": method,
                "error": f"不支持的方法: {method}（仅 GET/HEAD/POST）"}
    try:
        cap = max(256, min(int(max_body or 4000), 20000))
    except (TypeError, ValueError):
        cap = 4000
    send_headers, header_problems = _clean_headers(headers, cookie)
    data = body.encode("utf-8") if (method == "POST" and body) else None
    if data is not None and not any(k.lower() == "content-type"
                                    for k in send_headers):
        send_headers["Content-Type"] = "application/x-www-form-urlencoded"

    try:
        req = urllib.request.Request(
            _allow_http_url(url), data=data, method=method,
            headers={"User-Agent": "XPentest/0.1 (authorized test)",
                     **send_headers})
        opener = urllib.request.build_opener(_NoRedirect)
        started = _time.perf_counter()
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            resp = exc            # 3xx 不跟随；4xx/5xx 也按响应返回
        try:
            raw = b"" if method == "HEAD" else resp.read(cap + 1)
            elapsed_ms = round((_time.perf_counter() - started) * 1000, 1)
            truncated = len(raw) > cap
            result = {
                "url": getattr(resp, "url", url),
                "method": method,
                "status": getattr(resp, "status", None)
                          or getattr(resp, "code", None),
                "reason": str(getattr(resp, "reason", "") or ""),
                "headers": [[k, str(v)[:300]]
                            for k, v in list(resp.headers.items())],
                "location": resp.headers.get("Location", ""),
                "body": raw[:cap].decode("utf-8", errors="replace"),
                "truncated": truncated,
                "elapsed_ms": elapsed_ms,
                "request_headers": _mask_headers(send_headers),
            }
            if header_problems:
                result["header_problems"] = header_problems
        finally:
            try:
                resp.close()
            except Exception:            # noqa: BLE001
                pass
        return result
    except Exception as exc:             # noqa: BLE001
        # 失败也要留痕"我们发了什么"——"尝试过但连不上"与"没试过"是两回事
        return {"url": url, "method": method, "error": str(exc)[:300],
                "request_headers": _mask_headers(send_headers),
                **({"header_problems": header_problems}
                   if header_problems else {})}


def register_builtins(registry) -> None:
    """注册内置工具到注册表。"""
    from penagent.tools import ToolSpec

    specs = [
        ToolSpec(name="port_scan",
                 description="TCP 端口扫描（指定端口列表，被动侦察）",
                 parameters={"host": {"type": "string"},
                             "ports": {"type": "string"}},
                 fn=port_scan),
        ToolSpec(name="http_probe",
                 description="HTTP 探测：状态码/Server/响应头/页面标题",
                 parameters={"url": {"type": "string"}},
                 fn=http_probe),
        ToolSpec(name="dns_lookup",
                 description="DNS 解析目标域名",
                 parameters={"domain": {"type": "string"}},
                 fn=dns_lookup),
        ToolSpec(name="robots_fetch",
                 description="抓取目标 robots.txt（信息收集）",
                 parameters={"base_url": {"type": "string"}},
                 fn=robots_fetch),
        ToolSpec(name="http_raw",
                 description=("HTTP 原始探测（本地直连）：状态行 + 完整响应头 + "
                              "正文片段 + 耗时；可带头/Cookie（注：CRLF 拒绝、凭据脱敏）；"
                              "不跟随重定向（3xx 带 location）、"
                              "4xx/5xx 按响应返回。用于精细判读——SPA 兜底页甄别、"
                              "响应头缺失判读、跳转链取证"),
                 parameters={"url": {"type": "string"},
                             "method": {"type": "string"},
                             "body": {"type": "string"},
                             "headers": {"type": "object"},
                             "cookie": {"type": "string"},
                             "timeout": {"type": "number"},
                             "max_body": {"type": "number"}},
                 fn=http_raw),
    ]
    for s in specs:
        registry.register(s)
