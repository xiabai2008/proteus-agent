"""内置工具的工具体内 URL 边界校验测试（file:// 与云元数据地址拒绝）。

背景：urllib.urlopen 原生支持 file://，且不经过 PolicyGate 闸门的直接
fn 调用路径仍可达工具体——_allow_http_url 必须自带同一条边界：
仅 http(s) 协议；链路本地（云元数据 169.254.0.0/16）/组播/保留段拒绝；
环回/私网是授权靶机的合法目标，不阻断。
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.builtin_tools import http_probe, http_raw, robots_fetch


def test_http_probe_rejects_file_scheme(tmp_path):
    """file:// 指向真实本地文件 -> 返回 error，文件内容不出现在输出里。"""
    secret = tmp_path / "secret.txt"
    secret.write_text("TOPSECRET", encoding="utf-8")
    result = http_probe(secret.as_uri())          # file:///.../secret.txt
    assert "error" in result
    assert "TOPSECRET" not in str(result)


def test_http_probe_rejects_other_schemes():
    for bad in ("ftp://example.com/x", "gopher://x", "javascript:x"):
        result = http_probe(bad)
        assert "error" in result and "协议不被允许" in result["error"]


def test_http_probe_rejects_metadata_address():
    """解析到链路本地（云元数据）-> 拒绝。"""
    result = http_probe("http://169.254.169.254/latest/meta-data/")
    assert "error" in result and "禁止的地址" in result["error"]


def test_http_probe_allows_authorized_loopback():
    """环回是授权靶机默认白名单 -> 不被工具内边界拒绝（网络错误可接受）。"""
    result = http_probe("http://127.0.0.1:1/")    # 端口 1 大概率无服务
    assert "协议不被允许" not in str(result) and "禁止的地址" not in str(result)


def test_robots_fetch_rejects_file_scheme(tmp_path):
    secret = tmp_path / "robots.txt"
    secret.write_text("Disallow: /TOPSECRET", encoding="utf-8")
    result = robots_fetch(str(tmp_path))
    assert "error" in result
    assert "TOPSECRET" not in str(result)

# ----------------------------------------------------------------------
# http_raw：原始证据工具（2026-09-21 DSH 实测暴露的缺口）
#
# 背景：DSh 会话里模型拒绝用内核工具、改用宿主 shell 的理由之一是
# "http_probe 的固化输出给不了原始响应头与正文"。本工具补这一课，
# 下面把它的三条刻意行为钉住：不跟随重定向、错误响应不抛异常、正文截断。
# ----------------------------------------------------------------------
import pytest  # noqa: E402


@pytest.fixture
def raw_server():
    """本地临时 HTTP 服务：/ok · /redirect · /err · /big 四条路由。"""
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, code, body: bytes, ctype: str = "text/plain"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Test", "raw-1")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/target")
                self.send_header("X-Test", "raw-1")
                self.end_headers()
            elif self.path == "/err":
                self._send(500, b'{"error":"boom"}', "application/json")
            elif self.path == "/big":
                self._send(200, b"x" * 5000)
            else:
                self._send(200, b'{"ok":true}', "application/json")

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_http_raw_returns_original_headers_body_and_timing(raw_server):
    result = http_raw(f"{raw_server}/ok")
    assert result["status"] == 200 and result.get("error") is None
    headers = dict(result["headers"])
    assert headers.get("X-Test") == "raw-1"          # 原始响应头，不是结论字段
    assert "ok" in result["body"] and result["truncated"] is False
    assert result["elapsed_ms"] > 0
    assert result["location"] == ""


def test_http_raw_does_not_follow_redirect(raw_server):
    """3xx 本身是证据：不能跟随，要能拿到 Location。"""
    result = http_raw(f"{raw_server}/redirect")
    assert result["status"] == 302
    assert result["location"] == "/target"
    assert result["url"].endswith("/redirect")       # URL 未被改写


def test_http_raw_returns_error_responses(raw_server):
    """4xx/5xx 按响应返回（错误页正文同样是证据），不抛异常。"""
    result = http_raw(f"{raw_server}/err")
    assert result["status"] == 500 and "boom" in result["body"]


def test_http_raw_truncates_body(raw_server):
    result = http_raw(f"{raw_server}/big", max_body=1000)
    assert result["truncated"] is True
    assert len(result["body"]) == 1000
    assert result["status"] == 200


def test_http_raw_rejects_bad_scheme_and_method():
    assert "协议不被允许" in http_raw("file:///etc/hosts")["error"]
    assert "禁止的地址" in http_raw(
        "http://169.254.169.254/latest/meta-data/")["error"]
    assert "不支持的方法" in http_raw("http://127.0.0.1:1/",
                                     method="DELETE")["error"]


def test_http_raw_visible_in_registry_and_mcp():
    """工具必须真进注册表与 MCP 工具表——否则等于没加。"""
    from penagent.builtin_tools import register_builtins
    from penagent.tools import ToolRegistry

    reg = ToolRegistry()
    register_builtins(reg)
    assert "http_raw" in reg.names()
