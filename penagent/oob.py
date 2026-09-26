"""盲打带外（OOB）结果回传收集器——`oob_read` 内核原语的底座。

为什么（REPORT §8.7-1，2026-09-26 attach 矩阵实测）：零回显靶（pickle 盲打）
上一靶 28 次调用全是外带假设试错。标准化解法是给 agent 一个**固定的回传
通道**：目标侧注入"出网回连"载荷（curl / wget / python urllib 均可），内核
侧收集器把回调请求原样记录，`oob_read` 一发收结果——外带假设从 N 种收窄
到 1 种。

设计要点：
- **只绑 127.0.0.1**：授权目标就是本机回环（Policy 白名单同口径），收集器
  不对局域网开放——它不是通用 HTTP 服务，是靶机回传的收件箱。
- **进程内单例、懒启动、幂等**：内核进程按 preset 常驻（§8.5），收集器随
  首次 `oob_read` 启动、跨调用存活；重复 start 同端口直接复用。
- **端口占用自动上移**：靶机环境端口拥挤，占用时依次 +1 试到 +10，实际
  端口回传给调用方（callback 字段以实际为准）。
- **留痕上限**：每端口只保留最近 100 条（防盲打载荷刷爆内存）。
- 回调一律回 200 + "ok"：不关心目标用什么协议语义，收到即算命中。
"""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# 每端口留痕上限（超出丢最旧）
MAX_HITS = 100
# 端口被占时向上重试的步数
PORT_RETRIES = 10
# 合法端口范围（拒绝特权口与越界值）
PORT_MIN, PORT_MAX = 1024, 65535

_lock = threading.Lock()
_servers: dict[int, ThreadingHTTPServer] = {}
_hits: dict[int, list[dict]] = {}


class _CallbackHandler(BaseHTTPRequestHandler):
    """把每个回调请求记成一条 hit：时间/来源/方法/路径/查询串/UA。"""

    def _capture(self) -> None:
        url = urlparse(self.path)
        hit = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "client": self.client_address[0],
            "method": self.command,
            "path": url.path,
            "query": {k: v[0] for k, v in parse_qs(url.query).items()},
            "user_agent": self.headers.get("User-Agent", ""),
        }
        port = self.server.server_address[1]
        with _lock:
            hits = _hits.setdefault(port, [])
            hits.append(hit)
            del hits[:-MAX_HITS]
        try:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # 目标侧不等响应很常见：记录已完成，回包丢了不算失败

    do_GET = _capture
    do_POST = _capture
    do_HEAD = _capture

    def log_message(self, *args) -> None:  # noqa: D401 —— 静默默认日志
        pass


def _start_locked(port: int) -> int:
    """启动（或复用）收集器，返回实际端口。调用方持有 _lock。

    端口被其它进程占用时依次上移重试；重试耗尽抛 OSError。
    """
    last_exc: OSError | None = None
    for candidate in range(port, port + PORT_RETRIES + 1):
        if candidate > PORT_MAX:
            break
        if candidate in _servers:
            return candidate                      # 已是我们启动的：直接复用
        try:
            server = ThreadingHTTPServer(("127.0.0.1", candidate),
                                         _CallbackHandler)
        except OSError as exc:
            last_exc = exc
            continue                              # 被占用：试下一个端口
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True,
                                  name=f"proteus-oob-{candidate}")
        thread.start()
        _servers[candidate] = server
        _hits.setdefault(candidate, [])
        return candidate
    raise OSError(f"端口 {port}~{candidate} 均无法绑定: {last_exc}")


def start(port: int) -> int:
    """启动收集器（幂等），返回实际监听端口。"""
    if not (PORT_MIN <= port <= PORT_MAX):
        raise ValueError(f"port 须在 {PORT_MIN}~{PORT_MAX}（收到 {port}）")
    with _lock:
        return _start_locked(port)


def read_hits(port: int, clear: bool = False) -> list[dict]:
    """取该端口的回调留痕；clear=True 时取走即清（下次从零计数）。

    读取时同样按 MAX_HITS 裁剪——写入路径已限长，这里是防御性双保险
    （外部直接操作 _hits 的测试/脚本不至于绕爆内存）。
    """
    with _lock:
        hits = list(_hits.get(port, []))[-MAX_HITS:]
        if clear:
            _hits[port] = []
    return hits


def callback_hint(port: int) -> str:
    """给 agent 的回连 URL 模板（载荷里 <tag>?data= 自定义）。"""
    return f"http://127.0.0.1:{port}/<tag>?data=<外带内容>"


def shutdown_all() -> None:
    """测试/收尾用：关掉全部收集器。"""
    with _lock:
        for server in _servers.values():
            server.shutdown()
        _servers.clear()
        _hits.clear()
