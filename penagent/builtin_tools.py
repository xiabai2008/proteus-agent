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


#: grep 的扫描上限（字符）：够覆盖常见目录列表/HTML 页，又不至于把内存吃满
GREP_SCAN_CAP = 65536


def _grep_body(text: str, pattern: str,
               max_matches: int = 20, max_lines: int = 10) -> dict:
    """在正文（扫描缓冲）里按正则提取：逐匹配 + 命中行两路返回。

    为什么要"逐匹配"：真实的目录列表页（如 Juice Shop 的 /ftp）把多个
    `<li><a href=...>` 挤在同一行，按行提取只会得到一条被截断的长行，模型
    仍然看不到清单。逐匹配则一个个给出。
    返回 {"pattern", "count", "matches": [...], "lines": [...]}；正则非法时
    返回 error 说明而不抛异常——工具的错误要能被模型读到并自我纠正。
    """
    import re as _re

    try:
        rx = _re.compile(pattern)
    except _re.error as exc:
        return {"pattern": pattern, "error": f"正则非法: {exc}"}

    matches = [m.group(0).strip()[:300] for m in rx.finditer(text)]
    lines = []
    for line in text.splitlines():
        if rx.search(line):
            lines.append(line.strip()[:300])
            if len(lines) >= max_lines:
                break
    return {"pattern": pattern, "count": len(matches),
            "matches": matches[:max_matches], "lines": lines}


def http_raw(url: str, method: str = "GET", body: str = "",
             headers=None, cookie: str = "", grep: str = "",
             timeout: float = 10.0, max_body: int = 1200) -> dict:
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

    `grep`（2026-09-22 补，来自真机教训）：正文太长时**别再加大 `max_body`**——
    内核把工具结果回灌给模型时按 2500 字符截断（`penagent/agent.py:477`），
    加大正文既看不见又烧步数。需要从长页面里取特定内容（目录列表里的文件名、
    表单 action、JS 里的接口路径）时用 `grep` 给正则，工具在**服务端**做提取、
    只把命中行回给你。实测场景：Juice Shop 的 `/ftp` 目录列表页内联 CSS 很长，
    文件清单在截断线之后，模型连续 13 步重试同一个请求——白烧一轮预算。

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
        cap = max(256, min(int(max_body or 1200), 20000))
    except (TypeError, ValueError):
        cap = 1200
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
            # 扫描缓冲比回给模型的正文大得多：grep 要在**完整页面**上做提取，
            # 否则"绕过截断"就没意义了（第一版就犯了这个错，测试当场抓住）
            scan = max(cap, GREP_SCAN_CAP)
            raw = b"" if method == "HEAD" else resp.read(scan + 1)
            elapsed_ms = round((_time.perf_counter() - started) * 1000, 1)
            truncated = len(raw) > cap
            text_body = raw[:cap].decode("utf-8", errors="replace")
            scan_text = raw[:scan].decode("utf-8", errors="replace")
            result = {
                "url": getattr(resp, "url", url),
                "method": method,
                "status": getattr(resp, "status", None)
                          or getattr(resp, "code", None),
                "reason": str(getattr(resp, "reason", "") or ""),
                "headers": [[k, str(v)[:300]]
                            for k, v in list(resp.headers.items())],
                "location": resp.headers.get("Location", ""),
                "body": text_body,
                "truncated": truncated,
                "elapsed_ms": elapsed_ms,
                "request_headers": _mask_headers(send_headers),
            }
            if truncated:
                result["note"] = (
                    "正文已截断——不要再加大 max_body（内核回灌给模型时按 2500"
                    " 字符截断，加大也看不见）。要从长页面取特定内容，改用 grep"
                    " 参数给正则，例如从目录列表页里取文件链接。")
            if grep:
                result["grep"] = _grep_body(scan_text, grep)
                result["grep"]["scanned_chars"] = len(scan_text)
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
                              "正文片段 + 耗时；可带头/Cookie（CRLF 拒绝、凭据脱敏）；"
                              "长页面用 grep 在服务端做定向提取；"
                              "不跟随重定向（3xx 带 location）、"
                              "4xx/5xx 按响应返回。用于精细判读——SPA 兜底页甄别、"
                              "响应头缺失判读、跳转链取证"),
                 parameters={"url": {"type": "string"},
                             "method": {"type": "string"},
                             "body": {"type": "string"},
                             "headers": {"type": "object"},
                             "cookie": {"type": "string"},
                             "grep": {"type": "string"},
                             "timeout": {"type": "number"},
                             "max_body": {"type": "number"}},
                 fn=http_raw),
    ]
    for s in specs:
        registry.register(s)
