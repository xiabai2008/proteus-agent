"""`oob_read` 盲打带外回传原语回归（REPORT §8.7-1 完整版）。

场景：零回显靶上 agent 注入"出网回连"载荷，内核收集器记回调，
`oob_read` 一发收结果——外带假设从 N 种收窄到 1 种。
"""
import json
import socket
import sys
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent import oob
from penagent.builtin_tools import oob_read


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _callback(url: str) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "oob-test/1.0"})
    urllib.request.urlopen(req, timeout=3).read()


def teardown_function():
    oob.shutdown_all()


def test_collector_captures_callback():
    port = oob.start(_free_port())
    _callback(f"http://127.0.0.1:{port}/exfil?data=flag%7Btest%7D")
    hits = oob.read_hits(port)
    assert len(hits) == 1
    hit = hits[0]
    assert hit["path"] == "/exfil"
    assert hit["query"]["data"] == "flag{test}"
    assert hit["client"] == "127.0.0.1"
    assert hit["method"] == "GET"
    assert hit["user_agent"] == "oob-test/1.0"


def test_start_is_idempotent_and_shifts_when_busy():
    """同端口重复 start 复用；被其它进程占用时自动上移。"""
    port = oob.start(_free_port())
    assert oob.start(port) == port                      # 幂等复用
    # 占住下一个端口，模拟冲突 → 实际端口应跳过它
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", port + 1))
    blocker.listen(1)
    port2 = oob.start(port + 1)
    assert port2 == port + 2
    blocker.close()


def test_oob_read_roundtrip():
    """工具层：首次调用起收集器，回连后再调一次收回带结果。"""
    port = _free_port()
    first = oob_read(port=port, wait=0)
    assert first["ok"] is True
    assert first["count"] == 0
    assert str(port) in first["callback"]               # callback 含实际端口
    assert first["callback"].startswith("http://host.docker.internal")
    scenarios = [c["scenario"] for c in first["callback_candidates"]]
    assert any("容器" in s for s in scenarios)           # 容器场景在候选里
    _callback(f"http://127.0.0.1:{first['port']}/n?data=leak")
    second = oob_read(port=port, wait=0)
    assert second["count"] == 1
    assert second["hits"][0]["query"]["data"] == "leak"


def test_oob_read_bind_all_exposes_bridge_candidates():
    """bind=all：绑 0.0.0.0（本机可回连），候选含网桥网关与局域网 IP。"""
    port = _free_port()
    r = oob_read(port=port, wait=0, bind="all")
    assert r["ok"] is True and r["bind"] == "all"
    urls = [c["url"] for c in r["callback_candidates"]]
    assert any("172.17.0.1" in u for u in urls)         # 网桥网关候选
    _callback(f"http://127.0.0.1:{r['port']}/a?data=x")  # 0.0.0.0 含回环
    assert oob_read(port=port, wait=0)["count"] == 1


def test_oob_read_rebind_same_port_switches_address():
    """同端口换绑：关旧实例绑新地址，历史留痕保留。"""
    port = _free_port()
    oob_read(port=port, wait=0, bind="loopback")
    r = oob_read(port=port, wait=0, bind="all")
    assert r["ok"] is True                              # 重绑成功不抛
    _callback(f"http://127.0.0.1:{port}/b")
    assert oob_read(port=port, wait=0)["count"] == 1


def test_rebind_releases_old_listener_socket():
    """换绑必须**留在同一端口**，且旧监听套接字真的释放（2026-10-01 CI 实测补）。

    `shutdown()` 只停 `serve_forever` 循环，**不关监听套接字**——只有
    `server_close()` 才关。少了它，POSIX 上紧接着绑同端口必 EADDRINUSE，
    于是 `_start_locked` 的"端口上移"容错把同端口换绑**悄悄换成换端口**，
    旧端口还留个半死监听（连接能进、没人接）。

    判据刻意落在"套接字已释放"而不是"端口号没变"：Windows 的 SO_REUSEADDR
    允许覆盖同端口绑定，端口号那半边在本机恒真、抓不到这个回归——上面
    `test_oob_read_rebind_same_port_switches_address` 就是这么被盖住的。
    """
    port = _free_port()
    oob.start(port, bind="loopback")
    stale = oob._servers[("127.0.0.1", port)]
    assert oob.start(port, bind="all") == port          # 留在同一端口
    assert stale.socket.fileno() == -1                  # 旧监听已释放
    assert ("127.0.0.1", port) not in oob._servers
    assert ("0.0.0.0", port) in oob._servers


def test_oob_read_clear_empties_hits():
    port = _free_port()
    oob_read(port=port, wait=0)
    _callback(f"http://127.0.0.1:{oob.start(port)}/a")
    cleared = oob_read(port=port, wait=0, clear=True)
    assert cleared["count"] == 1
    again = oob_read(port=port, wait=0)
    assert again["count"] == 0                          # 已清零


def test_oob_read_rejects_bad_port():
    r = oob_read(port=80)                               # 特权口
    assert r["ok"] is False
    assert "启动失败" in r["error"]
    r = oob_read(port=99999)
    assert r["ok"] is False


def test_oob_read_wait_is_capped(monkeypatch):
    """wait 上限 10s：传 999 不许真睡（防 agent 一次调用拖死预算）。"""
    slept = []
    monkeypatch.setattr("time.sleep", lambda s: slept.append(s))
    oob_read(port=_free_port(), wait=999)
    assert slept and slept[0] <= 10


def test_oob_hits_capped_at_100():
    """留痕上限：超过 100 条丢最旧，内存不随载荷刷量增长。"""
    port = oob.start(_free_port())
    for i in range(105):
        with oob._lock:
            oob._hits[port].append({"i": i})
    hits = oob.read_hits(port)
    assert len(hits) == oob.MAX_HITS
    assert hits[-1] == {"i": 104}


def test_oob_read_visible_in_ctf_web_mode():
    """ctf-web 模式白名单含 oob_read（allow + auto_approve 都要可解析）。"""
    from penagent.modes import load_mode

    mode = load_mode("ctf-web")
    assert mode.capability.allows("oob_read")
