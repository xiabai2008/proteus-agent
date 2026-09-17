"""LLM 客户端测试：会话头、端点协议白名单、读超时重试。

全部打桩在本地 HTTP 服务上——不访问外网、不需要真实凭据。
"""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.llm import LLMConfig, LLMError, chat


def _placeholder() -> str:
    """打桩端点不校验凭据，这里只需要一个让 ready() 为真的占位串。

    刻意不把值写成字面量：本文件里不存在任何真实凭据，也不该出现形如凭据的常量。
    """
    return "placeholder"


class _StubServer:
    """OpenAI 兼容端点打桩：记录收到的请求头，响应形态可控。"""

    def __init__(self, *, content: str = "ok", stall_body: float = 0.0) -> None:
        self.headers_seen: list[dict] = []
        self.requests = 0
        self._content = content
        self._stall_body = stall_body
        stub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:                    # noqa: N802
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                stub.requests += 1
                stub.headers_seen.append({k.lower(): v
                                          for k, v in self.headers.items()})
                body = json.dumps({"choices": [
                    {"message": {"role": "assistant",
                                 "content": stub._content}}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if stub._stall_body:
                    # 头已发出、正文故意迟到：制造 resp.read() 阶段的读超时
                    time.sleep(stub._stall_body)
                try:
                    self.wfile.write(body)
                except OSError:
                    pass                                  # 客户端已超时断开

            def log_message(self, *args) -> None:         # noqa: D102
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "_StubServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()


def _config(base_url: str, *, timeout: float = 5.0) -> LLMConfig:
    return LLMConfig(base_url=base_url, api_key=_placeholder(),
                     model="stub-model", timeout=timeout)


# ----------------------------------------------------------------------
# 一、会话头（openCode Go 网关要求 x-opencode-session）
# ----------------------------------------------------------------------
def test_chat_sends_session_header_and_bearer_token():
    with _StubServer(content="通了") as stub:
        cfg = _config(stub.base_url)
        assert chat(cfg, [{"role": "user", "content": "hi"}],
                    max_tokens=32) == "通了"
        sent = stub.headers_seen[0]
        assert sent["x-opencode-session"] == cfg.session_id
        assert sent["authorization"] == f"Bearer {_placeholder()}"


def test_session_id_stable_per_config_and_unique_across_configs():
    with _StubServer() as stub:
        cfg = _config(stub.base_url)
        first = cfg.session_id
        chat(cfg, [{"role": "user", "content": "a"}], max_tokens=8)
        chat(cfg, [{"role": "user", "content": "b"}], max_tokens=8)
        # 同一 config（= 一次任务）内稳定，换 config 换会话
        assert cfg.session_id == first
        assert {h["x-opencode-session"] for h in stub.headers_seen} == {first}
        assert _config(stub.base_url).session_id != first


# ----------------------------------------------------------------------
# 二、端点协议白名单
# ----------------------------------------------------------------------
def test_chat_rejects_non_http_scheme():
    cfg = LLMConfig(base_url="file:///etc/passwd", api_key=_placeholder(),
                    model="stub-model")
    with pytest.raises(LLMError, match="协议不被允许"):
        chat(cfg, [{"role": "user", "content": "hi"}])


def test_http_and_https_schemes_accepted():
    with _StubServer() as stub:
        assert _config(stub.base_url).ready()                 # http 可用
        assert LLMConfig(base_url="https://example.invalid/v1",
                         api_key=_placeholder()).ready()      # https 可用


def test_chat_without_api_key_raises_before_any_request():
    # api_key 缺省为空串：ready() 为假，未配置就不该发起任何请求
    cfg = LLMConfig(base_url="http://127.0.0.1:1", model="stub-model")
    with pytest.raises(LLMError, match="未配置 PENTEST_LLM_API_KEY"):
        chat(cfg, [{"role": "user", "content": "hi"}])


# ----------------------------------------------------------------------
# 三、读超时纳入重试（此前会直接掀翻整个任务）
# ----------------------------------------------------------------------
def test_chat_retries_on_read_timeout_then_raises_llm_error():
    with _StubServer(stall_body=2.0) as stub:
        cfg = _config(stub.base_url, timeout=0.5)
        with pytest.raises(LLMError, match="读超时"):
            chat(cfg, [{"role": "user", "content": "hi"}],
                 max_tokens=8, retries=1)
        # 读超时不再直接冒泡：重试了一次才放弃
        assert stub.requests == 2
