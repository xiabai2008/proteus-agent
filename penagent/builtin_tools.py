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
    ]
    for s in specs:
        registry.register(s)
