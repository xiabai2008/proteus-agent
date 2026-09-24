"""带会话态 HTTP 与报告导出测试（P1-1，2026-09-24）。

覆盖三件此前做不到的真实渗透动作：
- **登录后带着会话扫**：`session_http` 自动吸收 Set-Cookie、后续请求自动带上；
- **把证据里那条请求原样重放**：`replay_request` 比对状态码与正文哈希；
- **产出交付物**：`report_gen` 出 markdown / SARIF 2.1.0。

靶场用宿主机本地端口（`http.server`）——与 `tests/test_sandbox.py` 的
"反射靶页 fixture"同路子，不依赖任何外部服务，也不出网。
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent import http_session
from penagent.builtin_tools import report_gen
from penagent.evidence import EvidenceChain


# ----------------------------------------------------------------------
# 靶场：/login 设 cookie；/private 无 cookie 401、带 cookie 200；/counter 递增
# ----------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    hits = 0

    def log_message(self, *args):        # 静音
        pass

    def _send(self, code, body=b"", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        _Handler.hits += 1
        cookie = self.headers.get("Cookie", "")
        if self.path == "/login":
            self._send(200, b"<html>login form</html>",
                       [("Set-Cookie", "PHPSESSID=abc123; Path=/; HttpOnly"),
                        ("Set-Cookie", "role=admin; Path=/")])
        elif self.path == "/private":
            if "PHPSESSID=abc123" in cookie:
                self._send(200, b"<html>secret dashboard</html>")
            else:
                self._send(401, b"<html>unauthorized</html>")
        elif self.path == "/counter":
            self._send(200, f"<html>hit {_Handler.hits}</html>".encode())
        else:
            self._send(404, b"<html>not found</html>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        if self.path == "/login":
            self._send(302, b"", [("Location", "/private"),
                                  ("Set-Cookie", "PHPSESSID=abc123; Path=/")])
        else:
            self._send(404, b"nope")


@pytest.fixture(scope="module")
def lab():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture()
def session_dir(tmp_path):
    """把 jar 目录指到临时目录（避免污染仓库 data/）。"""
    http_session.configure(tmp_path / "data")
    yield tmp_path / "data"
    http_session.configure("data")
    http_session._session_state.clear()


# ----------------------------------------------------------------------
# 1. 会话：登录 → cookie 自动带 → 凭据不回显
# ----------------------------------------------------------------------
def test_login_then_private_with_session(lab, session_dir):
    before = http_session.session_http(f"{lab}/private", session="admin")
    assert before["status"] == 401 and before["cookie_names"] == []

    login = http_session.session_http(f"{lab}/login", session="admin")
    assert login["status"] == 200
    # 收到两个 Set-Cookie，但**只给名字**（凭据不回显）
    assert login["cookies_set"] == ["PHPSESSID", "role"]
    assert login["cookie_names"] == ["PHPSESSID", "role"]
    assert "abc123" not in json.dumps(login)

    after = http_session.session_http(f"{lab}/private", session="admin")
    assert after["status"] == 200 and "secret dashboard" in after["body"]


def test_sessions_are_isolated(lab, session_dir):
    http_session.session_http(f"{lab}/login", session="admin")
    anon = http_session.session_http(f"{lab}/private", session="guest")
    assert anon["status"] == 401                 # 另一个会话拿不到 cookie


def test_update_cookies_false_does_not_absorb(lab, session_dir):
    r = http_session.session_http(f"{lab}/login", session="admin",
                                  update_cookies=False)
    assert r.get("cookies_set") is None
    assert http_session.session_http(f"{lab}/private", session="admin")["status"] == 401


def test_jar_file_lives_under_data_dir(lab, session_dir):
    http_session.session_http(f"{lab}/login", session="admin")
    jar = session_dir / "http-sessions" / "admin.json"
    assert jar.is_file()
    stored = json.loads(jar.read_text(encoding="utf-8"))
    assert stored["cookies"]["PHPSESSID"] == "abc123"
    assert stored["log"][0]["request_id"].startswith("admin-")


# ----------------------------------------------------------------------
# 2. 重放：原样重发 + 比对
# ----------------------------------------------------------------------
def test_replay_reports_same_status_and_body(lab, session_dir):
    first = http_session.session_http(f"{lab}/private", session="admin",
                                      max_body=2000)
    # 先登录，再取一条稳定响应
    http_session.session_http(f"{lab}/login", session="admin")
    first = http_session.session_http(f"{lab}/private", session="admin",
                                      max_body=2000)

    replay = http_session.replay_request(first["request_id"], session="admin")
    assert replay["ok"] is True
    assert replay["verdict"]["same_status"] is True
    assert replay["verdict"]["same_body"] is True
    assert "可复现" in replay["verdict"]["hint"]


def test_replay_detects_dynamic_body(lab, session_dir):
    """正文变了但状态码一致 → 提示"动态内容，不是漏洞消失"（诚实界定）。"""
    entry = http_session.session_http(f"{lab}/counter", session="dyn",
                                      max_body=2000)
    replay = http_session.replay_request(entry["request_id"], session="dyn")
    assert replay["verdict"]["same_status"] is True
    assert replay["verdict"]["same_body"] is False
    assert "动态内容" in replay["verdict"]["hint"]


def test_replay_unknown_id_lists_available(lab, session_dir):
    http_session.session_http(f"{lab}/login", session="admin")
    result = http_session.replay_request("nope-0001", session="admin")
    assert result["ok"] is False
    assert "admin-0001" in result["error"]          # 给出可用 id，便于自纠


# ----------------------------------------------------------------------
# 3. 报告：markdown + SARIF
# ----------------------------------------------------------------------
def test_report_gen_markdown(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    chain = EvidenceChain(data / "chain.jsonl")
    chain.append("observation", {"tool": "http_raw", "url": "http://127.0.0.1/",
                                 "content": "status 200"})

    result = report_gen(data_dir=str(data))
    assert result["ok"] is True and result["format"] == "markdown"
    assert "证据链" in result["report"]


def test_report_gen_sarif_is_valid_container(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    chain = EvidenceChain(data / "chain.jsonl")
    chain.append("observation", {"tool": "http_raw", "url": "http://127.0.0.1/x",
                                 "mission": "m1"})
    chain.append("conclusion", {"mission": "m1", "summary": "发现 1 处"})

    result = report_gen(data_dir=str(data), format="sarif", out="r.sarif")
    assert result["ok"] is True
    report = json.loads(result["report"])
    assert report["version"] == "2.1.0"
    run = report["runs"][0]
    assert run["tool"]["driver"]["name"] == "proteus-agent"
    assert run["invocations"][0]["properties"]["chain_ok"] is True
    kinds = [r["properties"]["kind"] for r in run["results"]]
    assert kinds == ["observation", "conclusion"]
    assert run["results"][1]["level"] == "warning"
    assert (data / "reports" / "r.sarif").is_file()


def test_report_gen_rejects_path_escape(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    result = report_gen(data_dir=str(data), out="../escape.md")
    assert result["ok"] is False and "禁止路径分隔符" in result["error"]
