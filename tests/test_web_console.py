"""Web 控制台测试：模式/关键词、任务下发与步骤流、证据链视图。

后端直连 penagent（脚本化驱动走 SDK 内核路径，真实工具与判定器），
因此这些用例覆盖的是"控制台看到的确实来自内核"。
"""
import json
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from web.server import ConsoleHandler, ConsoleService

REPO_ROOT = PROJECT_ROOT


@pytest.fixture()
def service(tmp_path):
    return ConsoleService(data_dir=tmp_path / "data", repo_root=REPO_ROOT)


# ----------------------------------------------------------------------
# 一、模式与关键词触发
# ----------------------------------------------------------------------
def test_modes_expose_verifier_budget_and_triggers(service):
    modes = {m["id"]: m for m in service.modes()}
    assert {"pentest-standard", "ctf-web", "ctf-crypto"} <= set(modes)
    assert "base" not in modes                     # base 不作为运行模式暴露

    ctf = modes["ctf-web"]
    assert ctf["verifier"]["type"] == "flag_regex"
    assert ctf["budget"]["max_steps"] == 60
    assert ctf["triggers"]                          # 关键词触发词非空
    assert modes["pentest-standard"]["verifier"]["type"] == "evidence_chain"


def test_suggest_ranks_by_keyword_hits(service):
    hits = service.suggest("帮我解一道 CTF RSA 题，拿到 flag")
    ids = [h["id"] for h in hits]
    assert "ctf-crypto" in ids and "ctf-web" in ids
    assert hits[0]["id"] == "ctf-crypto"            # ctf + rsa 命中更多
    assert "ctf" in hits[0]["hits"]

    assert service.suggest("对目标做资产侦察与漏洞验证")[0]["id"] == \
        "pentest-standard"
    assert service.suggest("毫无相干的文本") == []


def test_unknown_mode_rejected(service):
    with pytest.raises(KeyError):
        service.mode("not-a-mode")


# ----------------------------------------------------------------------
# 二、任务下发与实时步骤流
# ----------------------------------------------------------------------
def _wait_mission(service, key, timeout=90.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = service.mission_state(key)
        if state["status"] == "error":
            raise AssertionError(f"任务失败: {state['error']}")
        if state["mission_id"]:
            return state["mission_id"]
        time.sleep(0.4)
    raise AssertionError("任务超时未产出作战记录")


def test_scripted_dispatch_streams_steps_and_flag(service):
    """验收路径：选 ctf-web 下发一题，步骤流来自 memory，判定给出 flag。"""
    task = service.dispatch("ctf-web", "127.0.0.1", "解出样例题的 flag",
                            driver="scripted", challenge="encoding-chain")
    mission_id = _wait_mission(service, task["key"])

    events = list(service.stream_events("ctf-web", mission_id, poll=0.2))
    steps = [e for e in events if e["type"] == "step"]
    verdict = [e for e in events if e["type"] == "verdict"]

    assert steps, "步骤流应有内容（来自 memory 的 mission steps）"
    assert all(s["step"].get("tool") for s in steps)
    assert verdict and verdict[-1]["outcome"] == "success"
    assert verdict[-1]["flag"] == "flag{layered_encodings_ok}"

    # 作战记录确实落进了该模式的记忆分区
    records = service.missions("ctf-web")
    assert any(r["id"] == mission_id for r in records)
    assert service.mission("ctf-web", mission_id)["outcome"] == "success"


def test_stego_flag_read_from_tool_output(service):
    """隐写题收口结论里没有 flag：判定语料含本任务工具输出（与判定器同源）。"""
    task = service.dispatch("ctf-web", "127.0.0.1", "解出样例题的 flag",
                            driver="scripted", challenge="b64-stego")
    mission_id = _wait_mission(service, task["key"])
    verdict = [e for e in service.stream_events("ctf-web", mission_id, poll=0.2)
               if e["type"] == "verdict"][-1]
    assert verdict["outcome"] == "success"
    assert verdict["flag"] == "flag{b64_stego_found}"


def test_unknown_challenge_rejected(service):
    task = service.dispatch("ctf-web", "127.0.0.1", "x",
                            driver="scripted", challenge="no-such")
    with pytest.raises(AssertionError, match="未知样例题"):
        _wait_mission(service, task["key"], timeout=30)


# ----------------------------------------------------------------------
# 三、证据链校验视图
# ----------------------------------------------------------------------
def test_evidence_view_reports_integrity_and_conclusion(service):
    task = service.dispatch("ctf-web", "127.0.0.1", "解出样例题的 flag",
                            driver="scripted", challenge="encoding-chain")
    mission_id = _wait_mission(service, task["key"])

    view = service.evidence_view("ctf-web", mission_id)
    assert view["integrity"]["ok"] is True          # 链式哈希完整
    assert view["total"] > 0
    assert view["records"]
    conclusion = view["conclusion"]
    assert conclusion and "flag 命中" in conclusion["content"]["verdict"]


# ----------------------------------------------------------------------
# 四、HTTP 层（薄适配，只做连通性冒烟）
# ----------------------------------------------------------------------
def _local(url: str) -> str:
    """测试助手只允许访问本机测试服务器：限协议、限主机名。"""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1",
                                                          "localhost"):
        raise ValueError(f"测试助手只允许访问本机 http 服务: {url!r}")
    return url


@pytest.fixture()
def http_server(service):
    ConsoleHandler.service = service
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), ConsoleHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _get(url, timeout=60):
    with urllib.request.urlopen(_local(url), timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _post(url, payload, timeout=60):
    request = urllib.request.Request(
        _local(url), data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def test_http_api_roundtrip(http_server):
    modes = _get(f"{http_server}/api/modes")
    assert any(m["id"] == "ctf-web" for m in modes["modes"])

    suggestions = _post(f"{http_server}/api/suggest", {"text": "CTF 解题拿 flag"})
    assert suggestions["suggestions"]

    task = _post(f"{http_server}/api/tasks", {
        "mode": "ctf-web", "target": "127.0.0.1",
        "objective": "解出样例题的 flag", "driver": "scripted",
        "challenge": "encoding-chain"})
    assert task["status"] == "running"

    state = None
    for _ in range(60):
        state = _get(f"{http_server}/api/state/{task['key']}")
        if state["mission_id"]:
            break
        time.sleep(0.5)
    assert state and state["mission_id"]

    view = _get(f"{http_server}/api/evidence/ctf-web/{state['mission_id']}")
    assert view["integrity"]["ok"] is True

    # SSE：读到判定事件即收口
    with urllib.request.urlopen(
            _local(f"{http_server}/api/stream/{state['mission_id']}"
                   f"?mode=ctf-web"), timeout=60) as stream:
        for raw in stream:
            line = raw.decode("utf-8").strip()
            if line.startswith("data:"):
                event = json.loads(line[5:])
                if event["type"] == "verdict":
                    assert event["outcome"] == "success"
                    assert event["flag"] == "flag{layered_encodings_ok}"
                    break
