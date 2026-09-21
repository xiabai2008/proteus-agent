"""评测骨架单测：评分卡聚合、序列化往返、跨版本对比、skipped 语义。

不测真实跑题（那是 examples/benchmark.py 的运行路径），只测纯逻辑——
聚合口径与对比方向错了，评分卡就会骗人。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples"))

from benchmark import CaseResult, Scorecard, load, run, save  # noqa: E402


def _case(suite="ctf", cid="c1", passed=True, outcome="success", steps=3,
          category="recon", elapsed=0.5):
    return CaseResult(suite=suite, case_id=cid, category=category,
                      outcome=outcome, passed=passed, steps=steps,
                      elapsed_s=elapsed)


def test_skipped_excluded_from_pass_rate():
    """skipped 不进分母——环境缺失不等于能力不足。"""
    card = Scorecard(results=[
        _case(cid="a", passed=True),
        _case(cid="b", passed=False, outcome="failed"),
        _case(cid="c", outcome="skipped", passed=False),
    ])
    assert card.total == 3
    assert card.attempted == 2
    assert card.skipped == 1
    assert card.pass_rate == 0.5


def test_avg_steps_ignores_skipped_and_zero():
    card = Scorecard(results=[
        _case(cid="a", steps=4),
        _case(cid="b", steps=2),
        _case(cid="c", steps=0, outcome="skipped", passed=False),
    ])
    assert card.avg_steps == 3.0


def test_by_category_groups():
    card = Scorecard(results=[
        _case(cid="a", category="crypto", passed=True),
        _case(cid="b", category="crypto", passed=False, outcome="failed"),
        _case(cid="c", category="web", passed=True),
    ])
    cats = card.by_category()
    assert cats["crypto"]["passed"] == 1
    assert cats["crypto"]["attempted"] == 2
    assert cats["crypto"]["pass_rate"] == 0.5
    assert cats["web"]["pass_rate"] == 1.0


def test_roundtrip_preserves_results(tmp_path):
    card = Scorecard(driver="scripted", started_at="2026-01-01 00:00:00",
                     results=[_case(cid="a"),
                              _case(cid="b", passed=False, outcome="failed")])
    back = load(save(card, tmp_path / "run.json"))
    assert back.driver == "scripted"
    assert [r.case_id for r in back.results] == ["a", "b"]
    assert back.pass_rate == card.pass_rate


def test_compare_detects_fixed_and_regressed():
    """逐例对比：只看总分会被此消彼长掩盖，必须逐例给出方向。"""
    baseline = Scorecard(results=[
        _case(cid="fixed", passed=False, outcome="failed"),
        _case(cid="regressed", passed=True),
        _case(cid="same", passed=True),
    ])
    current = Scorecard(results=[
        _case(cid="fixed", passed=True),
        _case(cid="regressed", passed=False, outcome="failed"),
        _case(cid="same", passed=True),
    ])
    diff = current.compare(baseline)
    assert diff["fixed"] == ["ctf/fixed"]
    assert diff["regressed"] == ["ctf/regressed"]


def test_compare_counts_new_case_as_not_regressed():
    """基线里没有的用例不计为回归（只说明是新增）。"""
    baseline = Scorecard(results=[_case(cid="old", passed=True)])
    current = Scorecard(results=[_case(cid="old", passed=True),
                                 _case(cid="new", passed=False,
                                       outcome="failed")])
    diff = current.compare(baseline)
    assert diff["regressed"] == []
    assert diff["pass_rate"]["delta"] < 0      # 新增失败会拉低整体通过率


def test_unknown_suite_marked_skipped_not_crash():
    card = run(["ghost-suite"])
    assert card.total == 1
    assert card.results[0].outcome == "skipped"
    assert "未知套件" in card.results[0].detail


def test_pentest_target_and_port_are_passed_through():
    """渗透套件的靶地址可传——否则本机 8080 被占用时既没法指定靶、
    也没法触发 skipped 路径。"""
    card = run(["pentest"], pentest_port=59999)
    assert card.total == 1
    assert card.results[0].outcome == "skipped"
    assert "59999" in card.results[0].detail


def test_render_includes_summary_line():
    card = Scorecard(driver="scripted", started_at="t",
                     results=[_case(cid="a"), _case(cid="b", passed=False,
                                                     outcome="failed")])
    text = card.render()
    assert "PASS" in text and "FAIL" in text
    assert "1/2" in text


# ----------------------------------------------------------------------
# 07 靶场：路径解析（conftest 与直跑脚本共用同一份实现）
# ----------------------------------------------------------------------
def test_resolve_g07_prefers_env_var(monkeypatch, tmp_path):
    """`PENTEST_G07_ROOT` 优先于相邻布局。"""
    from penagent.envcfg import resolve_g07

    fake = tmp_path / "g07"
    (fake / "warfare").mkdir(parents=True)
    monkeypatch.setenv("PENTEST_G07_ROOT", str(fake))
    assert resolve_g07() == fake


def test_resolve_g07_returns_none_when_missing(monkeypatch, tmp_path):
    """找不到时返回 None——调用方据此 skip，而不是崩溃。"""
    from penagent import envcfg

    monkeypatch.setenv("PENTEST_G07_ROOT", str(tmp_path / "nope"))
    monkeypatch.setattr(envcfg, "g07_candidates",
                        lambda: (tmp_path / "also-nope",))
    assert envcfg.resolve_g07() is None


def test_ensure_g07_on_path_injects_syspath(monkeypatch, tmp_path):
    """解析成功后注入 sys.path（供本进程 import warfare）。"""
    import sys

    from penagent.envcfg import ensure_g07_on_path

    fake = tmp_path / "g07"
    (fake / "warfare").mkdir(parents=True)
    monkeypatch.setenv("PENTEST_G07_ROOT", str(fake))
    assert ensure_g07_on_path() == fake
    assert str(fake) in sys.path


# ----------------------------------------------------------------------
# 07 套件：缺失时跳过而非判失败
# ----------------------------------------------------------------------
def test_g07_suite_skipped_when_target_missing(monkeypatch):
    """07 靶场不可达 -> 整组 skipped（环境缺失不等于能力不足）。"""
    from penagent import envcfg

    monkeypatch.setattr(envcfg, "resolve_g07", lambda: None)
    card = run(["g07"])
    assert card.total == 1
    assert card.results[0].outcome == "skipped"
    assert card.results[0].suite == "g07"
    assert "07 靶场" in card.results[0].detail


def test_g07_suite_registered():
    """07 套件已进 SUITES 注册表（--suite g07 / all 可用）。"""
    from benchmark import SUITES

    assert "g07" in SUITES


# ----------------------------------------------------------------------
# 真实靶场基线：定义与套件
# ----------------------------------------------------------------------
def test_lab_definitions_wellformed():
    """靶定义结构自洽：id 唯一、每个靶有预期发现、路径以 / 开头。"""
    from lab import DEFAULT_URLS, LABS

    ids = [lab.id for lab in LABS]
    assert len(ids) == len(set(ids)), "靶 id 重复"
    assert all(lab.id in DEFAULT_URLS for lab in LABS), "缺默认地址"
    for lab in LABS:
        assert lab.findings, f"{lab.id} 没有预期发现"
        assert lab.hint, f"{lab.id} 缺不可达时的提示"
        names = [f.name for f in lab.findings]
        assert len(names) == len(set(names)), f"{lab.id} 发现名重复"
        assert all(f.path.startswith("/") for f in lab.findings)


def test_get_lab_unknown_returns_none():
    from lab import get_lab

    assert get_lab("ghost-lab") is None
    assert get_lab("dvwa") is not None


def test_lab_suite_skips_when_unreachable(monkeypatch):
    """靶不可达 -> 该项 skipped 并带启动提示（不是 failed）。"""
    import benchmark
    import lab

    monkeypatch.setattr(lab, "reachable", lambda url, **kw: False)
    results = benchmark.run_lab_suite(".")
    assert results
    assert all(r.outcome == "skipped" for r in results)
    assert all(r.suite == "lab" for r in results)
    assert any("不可达" in r.detail for r in results)


# ----------------------------------------------------------------------
# 渗透套件：断言必须落在响应内容上（防退化）
#
# 早期版本用子串匹配整段 JSON，`"server"` / `"title"` / `"disallow"` 这类
# **键名**恒真、`"/debug"` 命中的是 URL 字段——四条断言里三条恒真，套件必然
# 100%。下面两个用例一正一反把它钉住。
# ----------------------------------------------------------------------
def _patch_probes(monkeypatch, probes):
    import benchmark

    monkeypatch.setattr(benchmark, "_probe_target",
                        lambda host, port: probes)


def test_pentest_findings_all_false_when_nothing_matches(monkeypatch):
    """什么都不满足时，**每一条**断言都必须为 False（有恒真项即失败）。"""
    _patch_probes(monkeypatch, {
        "home": {"status": 404, "title": ""},
        "admin": {"status": 404},
        "debug": {"status": 404},
        "robots": {"disallow": []},
    })
    import benchmark

    findings = benchmark._pentest_findings("127.0.0.1", 1)
    truthy = [k for k, v in findings.items() if v]
    assert not truthy, f"以下断言恒真（不落在响应内容上）: {truthy}"


def test_pentest_findings_all_true_when_target_matches(monkeypatch):
    """演示靶的真实响应应让全部断言命中。"""
    _patch_probes(monkeypatch, {
        "home": {"status": 200, "title": "Demo Portal - Flask/2.3"},
        "admin": {"status": 401},
        "debug": {"status": 200},
        "robots": {"disallow": ["/admin", "/debug"]},
    })
    import benchmark

    findings = benchmark._pentest_findings("127.0.0.1", 1)
    missed = [k for k, v in findings.items() if not v]
    assert not missed, f"应全部命中，却漏了: {missed}"


def test_pentest_default_port_avoids_dvwa(monkeypatch):
    """默认端口不是 8080——本机 8080 常被真实靶场（DVWA）占用，
    套件不该打到别人的靶上。"""
    import inspect

    import benchmark

    sig = inspect.signature(benchmark.run_pentest_suite)
    assert sig.parameters["port"].default == 8090
    sig_run = inspect.signature(benchmark.run)
    assert sig_run.parameters["pentest_port"].default == 8090


def test_lab_suite_registered():
    from benchmark import SUITES

    assert "lab" in SUITES


# ----------------------------------------------------------------------
# agent 驱动的靶场评测：判定纯函数 + 套件接线
#
# 判定错了，评分卡就会骗人——这里逐条钉住判定口径：必须**与工具无关**、
# 必须有状态码、必须真的走到预期内容上；爬虫列出 URL 不算发现。
# ----------------------------------------------------------------------
def _rec(tool, args, output, ok=True):
    """构造一条证据记录（形状与 agent 写入的 tool_call 一致）。"""
    from penagent.evidence import EvidenceRecord

    return EvidenceRecord(seq=1, kind="tool_call",
                          content={"tool": tool, "args": args, "ok": ok,
                                   "output": str(output)})


def _finding(name="f", path="/", status=200, contains=""):
    from lab import Finding

    return Finding(name, path, status, contains)


def test_agent_lab_scoring_requires_status_evidence():
    """爬虫列出的 URL（无状态码）不算发现——观察到的 != 验证过的。"""
    from lab_agent import score_from_evidence

    crawl = _rec("katana_crawl", {"url": "http://h:80"},
                 "http://h:80 http://h:80/login.php")
    hits = score_from_evidence([_finding(path="/login.php")], [crawl])
    assert hits["f"] is False


def test_agent_lab_scoring_tool_agnostic():
    """内置 http_probe 与外部 httpx_probe 的字段名不同，判定都要认。"""
    from lab_agent import score_from_evidence

    builtin = _rec("http_probe", {"url": "http://h:80/a"},
                   {"url": "http://h:80/a", "status": 200})
    httpx = _rec("httpx_probe", {"target": "http://h:80/a"},
                 {"url": "http://h:80/a", "status_code": 200,
                  "input": "http://h:80/a", "path": "/a"})
    assert score_from_evidence([_finding(path="/a")], [builtin])["f"] is True
    assert score_from_evidence([_finding(path="/a")], [httpx])["f"] is True


def test_agent_lab_scoring_requires_marker_content():
    """状态码对但内容标记不在 -> 不算命中（防"看到 200 就记功"）。"""
    from lab_agent import score_from_evidence

    rec = _rec("http_probe", {"url": "http://h:80/docs"},
               {"url": "http://h:80/docs", "status": 200, "title": "x"})
    miss = score_from_evidence(
        [_finding(path="/docs", contains="Index of")], [rec])
    assert miss["f"] is False


def test_agent_lab_scoring_follows_redirect_chain():
    """3xx + 跳转目标被探过 -> 算发现（DVWA 的 / 就靠这条）。"""
    from lab_agent import score_from_evidence

    recs = [
        _rec("httpx_probe", {"target": "http://h:80"},
             {"url": "http://h:80", "status_code": 302,
              "location": "login.php", "input": "http://h:80"}),
        _rec("http_probe", {"url": "http://h:80/login.php"},
             {"url": "http://h:80/login.php", "status": 200,
              "title": "Login :: DVWA"}),
    ]
    hits = score_from_evidence(
        [_finding(path="/", contains="DVWA")], recs)
    assert hits["f"] is True


def test_agent_lab_scoring_query_value_agnostic():
    """端点的 query 值可变：agent 自选 q=test 也算命中 ?q= 那条预期。"""
    from lab_agent import score_from_evidence

    rec = _rec("http_probe",
               {"url": "http://h:80/rest/products/search?q=test"},
               {"url": "http://h:80/rest/products/search?q=test",
                "status": 200})
    hits = score_from_evidence(
        [_finding(path="/rest/products/search?q=")], [rec])
    assert hits["f"] is True


def test_agent_lab_scoring_ignores_failed_calls():
    """执行失败的工具调用（ok=False）不能算证据。"""
    from lab_agent import score_from_evidence

    rec = _rec("http_probe", {"url": "http://h:80/a"},
               {"url": "http://h:80/a", "status": 200}, ok=False)
    assert score_from_evidence([_finding(path="/a")], [rec])["f"] is False


def test_agent_lab_chain_gate_fails_case(monkeypatch, tmp_path):
    """证据链校验不过 -> 该靶判失败，不因"命中数对"而放过。

    传 `tmp_path` 作 root：套件会把原始素材落到 root 下，写 "." 会把产物
    落进仓库根（本用例最初就是这么污染工作树的）。
    """
    import lab
    import lab_agent
    import benchmark

    monkeypatch.setattr(lab, "reachable", lambda url, **kw: True)
    monkeypatch.setattr(
        lab_agent, "run_lab_agent",
        lambda lab_, base, workdir, llm, **kw: {
            "outcome": "success", "steps": 3, "summary": "",
            "elapsed_s": 1.0, "records": [],
            "chain": {"ok": False, "tampered": [2], "broken_links": []},
            "mission_id": "m1", "injected_skills": []})
    # LLM 就绪检查放行（不打真实模型）
    from penagent.llm import LLMConfig

    monkeypatch.setattr(LLMConfig, "ready", lambda self: True)

    results = benchmark.run_agent_lab_suite(str(tmp_path), max_steps=1)
    assert results
    assert all(r.outcome == "failed" for r in results)
    assert all("证据链校验失败" in r.detail for r in results)
    assert not (tmp_path.parent / "dvwa").exists(), "不该往 root 之外写"


def test_agent_lab_suite_skips_without_llm(monkeypatch, tmp_path):
    """LLM 未配置 -> 全部 skipped（不是 failed）。"""
    import benchmark
    from penagent.llm import LLMConfig

    monkeypatch.setattr(LLMConfig, "ready", lambda self: False)
    results = benchmark.run_agent_lab_suite(str(tmp_path))
    assert results
    assert all(r.outcome == "skipped" for r in results)
    assert all("LLM 未配置" in r.detail for r in results)


def test_agent_lab_suite_skips_unreachable(monkeypatch, tmp_path):
    """靶不可达 -> skipped 并带启动提示。"""
    import benchmark
    import lab
    from penagent.llm import LLMConfig

    monkeypatch.setattr(LLMConfig, "ready", lambda self: True)
    monkeypatch.setattr(lab, "reachable", lambda url, **kw: False)
    results = benchmark.run_agent_lab_suite(str(tmp_path))
    assert results
    assert all(r.outcome == "skipped" for r in results)
    assert any("不可达" in r.detail for r in results)


def test_agent_lab_workdir_is_root_not_nested(monkeypatch, tmp_path):
    """套件的工作目录就是 root 本身——曾经多套一层 agent-lab，产物写偏。"""
    import lab
    import lab_agent
    import benchmark
    from penagent.llm import LLMConfig

    seen = {}

    def _fake_run(lab_, base, workdir, llm, **kw):
        seen["workdir"] = str(workdir)
        seen.update(kw)
        return {"outcome": "success", "steps": 1, "summary": "",
                "elapsed_s": 0.1, "records": [],
                "chain": {"ok": True, "tampered": [], "broken_links": []},
                "mission_id": "m1", "injected_skills": []}

    monkeypatch.setattr(LLMConfig, "ready", lambda self: True)
    monkeypatch.setattr(lab, "reachable", lambda url, **kw: True)
    monkeypatch.setattr(lab_agent, "run_lab_agent", _fake_run)
    monkeypatch.setattr(lab_agent, "_save_raw", lambda run, path: None)

    root = tmp_path / "bench"
    benchmark.run_agent_lab_suite(str(root), max_steps=1, seed=True)
    assert seen["workdir"] == str(root), "工作目录不该再套一层"
    assert seen["seed"] is True, "--seed-skills 没有透传到运行侧"


def test_agent_lab_repeat_makes_one_case_per_round(monkeypatch, tmp_path):
    """`--repeat N` 每轮一条用例（case_id 带 #序号）——单轮分数有噪声，要看得见每轮。"""
    import lab
    import lab_agent
    import benchmark
    from penagent.llm import LLMConfig

    calls = []

    def _fake_run(lab_, base, workdir, llm, **kw):
        calls.append(kw.get("raw_name"))
        return {"outcome": "success", "steps": 1, "summary": "",
                "elapsed_s": 0.1, "records": [],
                "chain": {"ok": True, "tampered": [], "broken_links": []},
                "mission_id": "m1", "injected_skills": []}

    monkeypatch.setattr(LLMConfig, "ready", lambda self: True)
    monkeypatch.setattr(lab, "reachable", lambda url, **kw: True)
    monkeypatch.setattr(lab_agent, "run_lab_agent", _fake_run)
    monkeypatch.setattr(lab_agent, "_save_raw", lambda run, path: None)

    card = benchmark.run(["agent-lab"], workdir=tmp_path,
                         agent_labs=["dvwa"], agent_repeat=3)

    ids = [r.case_id for r in card.results]
    assert ids == ["dvwa#1", "dvwa#2", "dvwa#3"]
    assert card.attempted == 3
    # 每轮的原始素材分开落盘，否则复盘只剩最后一轮
    assert calls == ["last_run_r1.json", "last_run_r2.json",
                     "last_run_r3.json"]


def test_reset_sandbox_memory_guardrails(tmp_path):
    """清空只发生在 `<root>/<lab>/mem`；越界 lab_id 一律拒绝。

    这条是安全护栏：`--reset-memory` 清的是评测沙箱，一旦路径拼接被绕过
    就可能删到生产记忆库或目录树其它部分。
    """
    from lab_agent import _reset_sandbox_memory

    mem = tmp_path / "dvwa" / "mem" / "skills"
    mem.mkdir(parents=True)
    (mem / "s.json").write_text("{}", encoding="utf-8")
    keep = tmp_path / "juice-shop" / "mem"
    keep.mkdir(parents=True)
    prod = tmp_path / "prod" / "skills"
    prod.mkdir(parents=True)

    assert _reset_sandbox_memory(tmp_path, "dvwa") is True
    assert not (tmp_path / "dvwa" / "mem").exists()
    assert keep.exists(), "别的靶的记忆不该被连带删除"
    assert prod.exists()

    # 越界 lab_id：一律拒绝执行
    for bad in ("..", "../prod", "a/b", "a\\b", ""):
        assert _reset_sandbox_memory(tmp_path, bad) is False
    assert prod.exists()


def test_reset_memory_flag_reaches_run_lab_agent(monkeypatch, tmp_path):
    """`--reset-memory` 传到运行侧、且在建 agent 之前执行（先清后建）。"""
    import lab
    import lab_agent
    import benchmark
    from penagent.llm import LLMConfig

    order = []
    monkeypatch.setattr(LLMConfig, "ready", lambda self: True)
    monkeypatch.setattr(lab, "reachable", lambda url, **kw: True)
    monkeypatch.setattr(lab_agent, "_reset_sandbox_memory",
                        lambda workdir, lab_id: order.append(
                            f"reset:{lab_id}") or True)

    def _fake_build(lab_id, workdir, llm, max_steps):
        order.append(f"build:{lab_id}")

        class _Agent:
            memory = None

            def run(self, *a, **kw):
                class _R:
                    outcome, steps, summary = "success", 1, ""
                    mission_id = "m1"
                    injected_skills: list = []
                return _R()

        class _Ev:
            path = tmp_path / "chain.jsonl"

            def tail(self):
                return None

            def load(self):
                return []

            def verify(self):
                return {"ok": True, "tampered": [], "broken_links": []}

        return _Agent(), _Ev()

    monkeypatch.setattr(lab_agent, "_build_agent", _fake_build)
    monkeypatch.setattr(lab_agent, "_save_raw", lambda run, path: None)

    benchmark.run(["agent-lab"], workdir=tmp_path, agent_labs=["dvwa"],
                  agent_reset=True)

    assert order == ["reset:dvwa", "build:dvwa"], "必须是先清沙箱、再建 agent"


def test_agent_lab_labs_filter_passes_through(monkeypatch, tmp_path):
    """`--labs` 只跑指定靶（单靶迭代时不必付三靶的时间与花费）。"""
    import benchmark
    from penagent.llm import LLMConfig

    monkeypatch.setattr(LLMConfig, "ready", lambda self: False)
    card = benchmark.run(["agent-lab"], workdir=tmp_path,
                         agent_labs=["dvwa"])
    assert [r.case_id for r in card.results] == ["dvwa"]


def test_lab_ground_truth_expansion_pinned():
    """扩容后的预期发现要留着——清单被误删会让分数虚高。"""
    from lab import get_lab

    names = {lab_id: {f.name for f in get_lab(lab_id).findings}
             for lab_id in ("dvwa", "juice-shop", "sw-secure-lab")}
    assert {"installer", "dir-listing-vulns", "mirror-dir",
            "config-sample"} <= names["dvwa"]
    assert {"dir-listing-ftp", "confidential-doc", "backup-file",
            "whoami", "users-api", "feedbacks-api", "quantitys-api",
            "languages-api"} <= names["juice-shop"]
    assert {"scenario-s01", "scenario-s02", "scenario-s03", "scenario-s04",
            "scenario-s05", "scenario-s06", "scenario-s07"} <= \
        names["sw-secure-lab"]


def test_lab_ground_truth_excludes_spa_fallback_paths():
    """Juice Shop 的 SPA 兜底路径不得入清单（200 但其实是首页）。

    实测：`/sitemap.xml`、`/.git/config` 与"随机不存在路径"返回同一份
    index.html。把它们当预期发现等于奖励假阳性。
    """
    from lab import get_lab

    paths = {f.path for f in get_lab("juice-shop").findings}
    for bogus in ("/sitemap.xml", "/.git/config", "/.git/HEAD"):
        assert bogus not in paths, f"{bogus} 是 SPA 兜底页，不该当预期发现"


def test_lab_ground_truth_markers_are_observable():
    """有标记的发现，标记必须来自**探测输出里看得见的**字段。

    `http_probe` 只返回状态/头/标题，不返回正文——标记若取自正文
    （如 /ftp/acquisitions.md 的 "confidential"），判定永远命中不了。
    这条把"标记可用"钉住：每条带标记的路径，探一次必须能看到该标记。
    """
    from lab import DEFAULT_URLS, LABS, _kernel_registry, reachable

    registry = None
    for lab in LABS:
        base = DEFAULT_URLS.get(lab.id, "")
        if not base or not reachable(base):
            continue          # 靶不在时跳过（环境缺失不等于失败）
        if registry is None:
            registry = _kernel_registry()
        for f in lab.findings:
            if not f.expect_contains:
                continue
            result = registry.execute("http_probe", {"url": base + f.path})
            blob = str(result.output)
            assert f.expect_contains in blob, (
                f"{lab.id}{f.path} 的标记 {f.expect_contains!r} "
                f"在探测输出里看不到: {blob[:160]}")


def test_agent_lab_registered_and_excluded_from_all():
    """套件已注册；`--suite all` 不含它（真 LLM 有花费，需显式点名）。"""
    from benchmark import ALL_SUITES_EXCLUDE, SUITES

    assert "agent-lab" in SUITES
    assert "agent-lab" in ALL_SUITES_EXCLUDE


def test_agent_lab_objective_does_not_leak_paths():
    """任务提示词不列预期路径——列了就变成脚本化填空，量不出自主侦察。"""
    from lab_agent import mission_objective

    text = mission_objective("http://127.0.0.1:8080")
    for leaked in ("/docs", "/robots.txt", "/rest/products/search",
                   "/api/Products", "login.php"):
        assert leaked not in text, f"提示词泄漏了预期路径 {leaked}"
