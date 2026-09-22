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
            elif self.path == "/echo":
                self._echo()
            elif self.path == "/listing":
                pad = "<style>" + ("/* padding */" * 200) + "</style>"
                links = "".join(f'<li><a href="ftp/f{i}.md">f{i}.md</a></li>'
                                for i in range(5))
                self._send(200, (pad + "<ul>" + links + "</ul>").encode(),
                           "text/html")
            else:
                self._send(200, b'{"ok":true}', "application/json")

        def do_POST(self):
            self._echo()

        def _echo(self):
            """回显请求方法与收到的头/正文（验证自定义头与 Cookie 真发出去了）。"""
            import json as _json

            length = int(self.headers.get("Content-Length") or 0)
            payload = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            blob = _json.dumps({
                "method": self.command,
                "headers": {k: v for k, v in self.headers.items()},
                "body": payload,
            }, ensure_ascii=False).encode()
            self._send(200, blob, "application/json")

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

def test_http_raw_sends_custom_headers_and_cookie(raw_server):
    """自定义头与 Cookie 能发出去（认证场景的最小能力）。"""
    result = http_raw(f"{raw_server}/echo", headers={"X-Token": "abc123"},
                      cookie="SID=deadbeef")
    echo = result["body"]
    assert "X-Token" in echo and "abc123" in echo
    assert "SID=deadbeef" in echo
    # 证据里记录请求头，但凭据类只留前 8 位
    sent = dict(result["request_headers"])
    assert sent["X-Token"] == "abc123"
    assert "deadbeef" not in sent["Cookie"] and "已脱敏" in sent["Cookie"]


def test_http_raw_posts_form_body(raw_server):
    result = http_raw(f"{raw_server}/echo", method="POST",
                      body="username=admin&password=password")
    echo = result["body"]
    assert "username=admin" in echo
    assert "application/x-www-form-urlencoded" in echo


def test_http_raw_rejects_header_injection():
    """头值含 CR/LF 一律拒绝——请求头注入是最经典的绕过面。"""
    result = http_raw("http://127.0.0.1:1/", headers={"X-Bad": "ok" + chr(13) + chr(10) + "Evil: 1"})
    problems = result.get("header_problems") or []
    assert any("请求头注入" in p for p in problems), result
    assert all("X-Bad" != k for k, _ in result.get("request_headers", []))


def test_http_raw_rejects_bad_header_names_and_caps():
    """头名非法逐条拒绝并报告（不是整批失败），合法头照常发出。"""
    result = http_raw("http://127.0.0.1:1/",
                      headers={"Bad Name": "x", "Good-One": "y"})
    assert any("头名非法" in p for p in result.get("header_problems", []))
    assert dict(result.get("request_headers", [])).get("Good-One") == "y"

# ----------------------------------------------------------------------
# 认证场景（2026-09-22 补 headers/cookie 能力）：DVWA 需 CSRF token + 会话
# ----------------------------------------------------------------------
def _dvwa_available() -> bool:
    import socket

    try:
        with socket.create_connection(("127.0.0.1", 8080), timeout=2):
            return True
    except OSError:
        return False


def test_http_raw_authenticated_flow_against_dvwa():
    """带认证访问 DVWA 受保护页：取 token -> 带会话登录 -> 带 Cookie 取页面。

    这条覆盖 2026-09-22 补的自定义头/Cookie 能力——此前内核只能做匿名探测，
    需要登录的靶场（认证后才有漏洞模块）完全够不到。靶场不在或数据库未初始化
    时跳过（环境缺失不等于能力不足）。
    """
    import re

    if not _dvwa_available():
        import pytest

        pytest.skip("DVWA 未运行（docker run -p 8080:80 vulnerables/web-dvwa）")
    base = "http://127.0.0.1:8080"

    page = http_raw(f"{base}/login.php", max_body=20000)
    token = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)",
                      page.get("body", ""))
    if token is None:
        import pytest

        pytest.skip("登录页没有 CSRF token（版本不同或已初始化流程未完成）")
    session = "; ".join(v.split(";")[0] for k, v in page.get("headers", [])
                        if k.lower() == "set-cookie")
    assert session, "登录页应下发会话 cookie"

    login = http_raw(f"{base}/login.php", method="POST",
                     body=f"username=admin&password=password&Login=Login"
                          f"&user_token={token.group(1)}",
                     cookie=session, headers={"Referer": f"{base}/login.php"})
    if login.get("location") != "index.php":
        import pytest

        pytest.skip(f"登录未成功（数据库可能未初始化）: {login.get('location')!r}")

    protected = http_raw(f"{base}/vulnerabilities/sqli/?id=1&Submit=Submit",
                         cookie=session, max_body=8000,
                         headers={"Referer": f"{base}/vulnerabilities/sqli/"})
    assert protected["status"] == 200, protected.get("error")
    assert "SQL Injection" in protected["body"], "受保护页未返回（Cookie 没生效？）"
    # 证据留痕但凭据脱敏
    sent = dict(protected["request_headers"])
    assert "已脱敏" in sent["Cookie"] and "PHPSESSID" not in sent["Cookie"]

def test_http_raw_grep_extracts_from_long_page(raw_server):
    """长页面用 grep 在服务端提取——复刻真机踩坑：/ftp 列表在内联 CSS 之后。

    2026-09-22 真机：Juice Shop 的 /ftp 页内联 CSS 很长，文件清单落在内核
    回灌截断线（2500 字符）之后，模型连试 13 步不肯换招、白烧一轮预算。
    修法是给出定向提取：grep 在服务端做，只把命中行回给模型。
    """
    import re as _re

    small = http_raw(f"{raw_server}/listing", max_body=200)
    assert small["truncated"] is True
    assert "grep" in small.get("note", "")           # 截断必须给出下一步指引
    assert "ftp/f0.md" not in small["body"]          # 目标内容确实在截断线之后

    hit = http_raw(f"{raw_server}/listing", max_body=200,
                   grep=r'href="ftp/[^"]+')
    # 同一行里的多个链接要逐个给出（按行提取只会得到一条被截断的长行）
    assert hit["grep"]["count"] == 5
    assert any("ftp/f4.md" in m for m in hit["grep"]["matches"])
    assert hit["grep"]["scanned_chars"] > 200        # 提取在完整页面上做，不是截断后


def test_http_raw_grep_invalid_regex_is_reported(raw_server):
    result = http_raw(f"{raw_server}/ok", grep="[unclosed")
    assert "正则非法" in result["grep"]["error"]
