"""盲打带外（OOB）结果回传收集器——`oob_read` 内核原语的底座。

为什么（REPORT §8.7-1，2026-09-26 attach 矩阵实测）：零回显靶（pickle 盲打）
上一靶 28 次调用全是外带假设试错。标准化解法是给 agent 一个**固定的回传
通道**：目标侧注入"出网回连"载荷（curl / wget / python urllib 均可），内核
侧收集器把回调请求原样记录，`oob_read` 一发收结果——外带假设从 N 种收窄
到 1 种。

设计要点：
- **默认只绑 127.0.0.1**：授权目标即本机回环（Policy 白名单同口径）。
  Docker Desktop 的容器可经 `host.docker.internal` 到达宿主回环（vpnkit
  转发），所以**容器靶的首选回连地址是 host.docker.internal**，默认绑定
  即可收到（2026-09-27 修复：此前提示用 127.0.0.1，容器里那是容器自己）。
- **bind="all" 供非 Docker Desktop 场景**：Linux 原生 docker 无
  host.docker.internal，容器要走网关 IP（172.17.0.1），此时收集器需绑
  0.0.0.0 才收得到——面向局域网开放，仅授权环境使用。
- **进程内单例、懒启动、幂等**：内核进程按 preset 常驻（§8.5），收集器随
  首次 `oob_read` 启动、跨调用存活；重复 start 同端口直接复用；同端口
  换绑地址时先关旧实例再重绑。
- **端口占用自动上移**：靶机环境端口拥挤，占用时依次 +1 试到 +10，实际
  端口回传给调用方（callback 字段以实际为准）。
- **留痕上限**：每端口只保留最近 100 条（防盲打载荷刷爆内存）。
- 回调一律回 200 + "ok"：不关心目标用什么协议语义，收到即算命中。
"""
from __future__ import annotations

import socket
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
_servers: dict[tuple[str, int], ThreadingHTTPServer] = {}
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


def _start_locked(port: int, bind_host: str) -> int:
    """启动（或复用）收集器，返回实际端口。调用方持有 _lock。

    端口被其它进程占用时依次上移重试；重试耗尽抛 OSError。
    同端口换绑地址：关旧实例再绑新地址（hits 保留，不丢历史留痕）——
    不同 bind 的同端口实例并存只会让回调进"错的一半"，收件箱必须唯一。
    """
    last_exc: OSError | None = None
    for candidate in range(port, port + PORT_RETRIES + 1):
        if candidate > PORT_MAX:
            break
        if (bind_host, candidate) in _servers:
            return candidate                      # 已是我们启动的：直接复用
        for key, srv in list(_servers.items()):
            if key[1] == candidate:
                try:
                    srv.shutdown()
                except Exception:  # noqa: BLE001 —— 关旧失败不挡重绑
                    pass
                del _servers[key]
        try:
            server = ThreadingHTTPServer((bind_host, candidate),
                                         _CallbackHandler)
        except OSError as exc:
            last_exc = exc
            continue                              # 被占用：试下一个端口
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True,
                                  name=f"proteus-oob-{candidate}")
        thread.start()
        _servers[(bind_host, candidate)] = server
        _hits.setdefault(candidate, [])
        return candidate
    raise OSError(f"端口 {port}~{candidate} 均无法绑定: {last_exc}")


def lan_ip() -> str:
    """本机局域网出口 IP（UDP connect 取路由源地址，不发任何包）。

    取不到返回空串（无外网路由/受限环境）——调用方按空值跳过该候选。
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return ""


def start(port: int, bind: str = "loopback") -> int:
    """启动收集器（幂等），返回实际监听端口。

    bind="loopback"（默认）：绑 127.0.0.1——同宿主进程与 Docker Desktop
    容器（经 host.docker.internal 转发到宿主回环）都能到达；
    bind="all"：绑 0.0.0.0——Linux 原生 docker 容器经网关 IP 回连时必需，
    面向局域网开放，仅授权环境使用。
    """
    if not (PORT_MIN <= port <= PORT_MAX):
        raise ValueError(f"port 须在 {PORT_MIN}~{PORT_MAX}（收到 {port}）")
    bind_host = "0.0.0.0" if bind == "all" else "127.0.0.1"
    with _lock:
        return _start_locked(port, bind_host)


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


def callback_hints(port: int, bind: str = "loopback") -> dict:
    """给 agent 的回连地址候选，按场景标注——载荷里选可达的那个用。"""
    primary = f"http://host.docker.internal:{port}"   # 容器首选
    cands = [
        {"url": primary,
         "scenario": "Docker 容器靶（首选；Docker Desktop 转发到宿主回环，"
                     "默认绑定即可达）"},
        {"url": f"http://127.0.0.1:{port}",
         "scenario": "目标进程与收集器同宿主（非容器）"},
    ]
    if bind == "all":
        cands.append({"url": f"http://172.17.0.1:{port}",
                      "scenario": "Linux 原生 docker 默认网桥网关"})
        ip = lan_ip()
        if ip:
            cands.append({"url": f"http://{ip}:{port}",
                          "scenario": "宿主局域网 IP（自定义 docker 网络可试）"})
    return {"primary": primary, "candidates": cands}


def shutdown_all() -> None:
    """测试/收尾用：关掉全部收集器。"""
    with _lock:
        for server in _servers.values():
            server.shutdown()
        _servers.clear()
        _hits.clear()
