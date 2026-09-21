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
