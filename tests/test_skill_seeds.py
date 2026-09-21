"""预置技能种子测试：能入库、能匹配、能进提示词、不覆盖学习结果。

为什么这些必须测：技能种子的价值全在"**真的会被注入**"上——指纹写错
（关键词不共现）、类别写错（被模式技能包过滤掉）、提示词模板不渲染，
任何一处出错都是**静默失效**：运行照跑、分数不动、看不出哪里坏了。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from penagent.agent import PenAgent                                    # noqa: E402
from penagent.evidence import EvidenceChain                            # noqa: E402
from penagent.memory import Memory, Skill                              # noqa: E402
from penagent.modes import load_mode                                   # noqa: E402
from penagent.skill_seeds import SEED_SKILLS, seed_skills              # noqa: E402
from penagent.tools import ToolRegistry                                # noqa: E402

# 生产口径的目标指纹（penagent/cli.py 的 _auto_fingerprint 形如 "<host> web service"）
PROD_FINGERPRINT = "127.0.0.1 web service"


def _agent(tmp_path: Path, memory: Memory) -> PenAgent:
    return PenAgent(ToolRegistry(), memory,
                    EvidenceChain(tmp_path / "chain.jsonl"),
                    mode=load_mode("pentest-standard"))


def test_all_seeds_survive_injection_top3_limit(tmp_path):
    """所有种子都要能进提示词——注入上限是 **3 条**（skills[-3:]）。

    超出的技能会**静默**不进提示词（不报错、分数不动，同 R-20 那类失效）。
    这条把容量钉住：种子加到第 4 条时这里直接失败，提醒先合并/取舍，
    而不是让某条知识悄悄失效。
    """
    memory = Memory(tmp_path / "mem")
    agent = _agent(tmp_path, memory)
    seed_skills(agent.memory)

    matched = agent.memory.find_skills(PROD_FINGERPRINT)
    ranked = agent._rank_skills(matched, PROD_FINGERPRINT)
    injected = {s.id for s in ranked[-3:]}

    missing = {s.id for s in SEED_SKILLS} - injected
    assert not missing, (
        f"这些种子进不了提示词（注入上限 3 条，当前 {len(SEED_SKILLS)} 条）: "
        f"{sorted(missing)}")
    assert len(SEED_SKILLS) <= 3, "种子超过注入容量，需要合并或改注入上限"


def test_seed_ids_pinned():
    """三条种子一个都不能少（删掉等于把量出来的教训丢了）。"""
    ids = {s.id for s in SEED_SKILLS}
    assert {"web-api-family-enum", "web-dir-listing-enum",
            "web-catchall-discriminate"} <= ids


def test_seed_skills_idempotent(tmp_path):
    """重复写入不重复：第二次全部 skipped。"""
    memory = Memory(tmp_path / "mem")

    first = seed_skills(memory)
    assert len(first["added"]) == len(SEED_SKILLS)
    assert first["skipped"] == []

    second = seed_skills(memory)
    assert second["added"] == []
    assert sorted(second["skipped"]) == sorted(s.id for s in SEED_SKILLS)
    assert len(memory.list_skills()) == len(SEED_SKILLS)


def test_seed_skills_does_not_clobber_learning(tmp_path):
    """已存在的技能不被种子覆盖——复用统计（成功率/次数）是学习结果。"""
    memory = Memory(tmp_path / "mem")
    seed_skills(memory)
    target = SEED_SKILLS[0].id
    skill = next(s for s in memory.list_skills() if s.id == target)
    skill.record_outcome(success=True)
    memory.update_skill(skill)

    seed_skills(memory)                      # 再种一次

    after = next(s for s in memory.list_skills() if s.id == target)
    assert after.attempts == 1 and after.success_rate == 1.0


def test_seed_refresh_updates_body_keeps_stats(tmp_path):
    """`refresh=True` 覆盖技能正文，但保留学习统计——知识迭代不清零成绩。"""
    import json

    memory = Memory(tmp_path / "mem")
    seed_skills(memory)
    target = SEED_SKILLS[0].id
    path = memory.skills_dir / f"{target}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["steps"] = ["旧正文"]
    data["successes"], data["attempts"], data["success_rate"] = 3, 4, 0.75
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    report = seed_skills(memory, refresh=True)

    assert target in report["refreshed"]
    after = next(s for s in memory.list_skills() if s.id == target)
    assert "旧正文" not in after.steps            # 正文换成种子里的新定义
    assert (after.successes, after.attempts) == (3, 4)
    assert after.success_rate == 0.75


def test_seed_without_refresh_leaves_body(tmp_path):
    """不带 refresh 时正文不动（默认幂等）。"""
    import json

    memory = Memory(tmp_path / "mem")
    seed_skills(memory)
    target = SEED_SKILLS[0].id
    path = memory.skills_dir / f"{target}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["steps"] = ["旧正文"]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    seed_skills(memory)

    after = next(s for s in memory.list_skills() if s.id == target)
    assert after.steps == ["旧正文"]


def test_seed_skills_written_as_copy(tmp_path):
    """入库的是副本：模块级常量不被 add_skill 写的运行时字段污染。"""
    memory = Memory(tmp_path / "mem")
    seed_skills(memory)
    assert SEED_SKILLS[0].created_at == ""


def test_seed_skills_match_production_fingerprint_and_survive_filter(
        tmp_path):
    """种子的指纹要能命中目标、类别要能过模式过滤——否则静默失效。

    匹配（find_skills 关键词共现）与过滤（mode.skills 类别白名单）是两道
    独立的门，任一不过技能都进不了提示词。

    **必须用 `agent.memory` 断言**：`Memory(root)` 与
    `Memory(root).for_namespace(模式)` 是两个目录，往前者种、agent 读后者，
    是不报错的静默失效（本用例最初就是这么写的，被 `agent.memory` 抓出）。
    """
    memory = Memory(tmp_path / "mem")
    agent = _agent(tmp_path, memory)
    seed_skills(agent.memory)                # 种到 agent 实际读取的那个 memory

    matched = agent.memory.find_skills(PROD_FINGERPRINT)
    assert matched, "预置技能未命中生产口径指纹"
    kept = agent._filter_mode_skills(matched)
    assert {s.id for s in kept} >= {s.id for s in SEED_SKILLS}


def test_seeding_wrong_namespace_is_invisible(tmp_path):
    """反向钉住：种到默认分区时 agent 看不到（防止有人"修"回去）。"""
    memory = Memory(tmp_path / "mem")
    agent = _agent(tmp_path, memory)
    seed_skills(memory)                      # 故意种到默认分区
    assert agent.memory.find_skills(PROD_FINGERPRINT) == []
    assert memory.find_skills(PROD_FINGERPRINT), "默认分区里确实写进去了"


def test_seed_skills_reach_system_prompt(tmp_path):
    """注入链路的终点：技能正文出现在 system prompt 里。"""
    memory = Memory(tmp_path / "mem")
    agent = _agent(tmp_path, memory)
    seed_skills(agent.memory)
    skills = agent._filter_mode_skills(
        agent.memory.find_skills(PROD_FINGERPRINT))

    system = agent._system_prompt(skills)

    assert "端点族枚举" in system
    # 断言落在**指导正文**上而非标题：标题会随知识迭代改，正文里的纪律
    # （先横后纵 / 限量）才是要注入到提示词里的东西
    assert "先横后纵" in system
    assert "先挑高风险的前 5 个" in system


def test_cli_seed_into_mode_namespace(tmp_path, capsys):
    """CLI 种子入口：`skills --seed --mode pentest-standard` 落到模式分区。

    这条替代不了端到端跑一次 agent，但能挡住"入口写错分区"这类静默失效。
    """
    from types import SimpleNamespace

    from penagent.cli import cmd_skills

    args = SimpleNamespace(data=str(tmp_path / "data"), seed=True,
                           mode="pentest-standard")
    assert cmd_skills(args) == 0
    out = capsys.readouterr().out
    assert "目标分区: pentest-standard" in out
    assert f"新增 {len(SEED_SKILLS)} 条" in out

    # 幂等：再种一次全跳过，且 agent 视角能看到
    assert cmd_skills(args) == 0
    agents_view = Memory(tmp_path / "data").for_namespace("pentest-standard")
    assert len(agents_view.list_skills()) == len(SEED_SKILLS)


def test_seed_skill_fingerprints_are_keyword_matchable():
    """指纹的写法约定：必须与生产指纹有非数字关键词交集。

    纯数字 token（IP / 端口）在 find_skills 里被过滤，指纹里只写它们是
    死字符串。
    """
    import re

    prod_words = set(re.findall(r"[a-z0-9]+", PROD_FINGERPRINT.lower()))
    prod_words = {w for w in prod_words if not w.isdigit()}
    for skill in SEED_SKILLS:
        words = set(re.findall(r"[a-z0-9]+", skill.target_fingerprint.lower()))
        words = {w for w in words if not w.isdigit()}
        assert words & prod_words, f"{skill.id} 指纹与生产指纹无交集"


def test_seed_skill_categories_allowed_by_pentest_mode():
    """种子的 category 必须在 pentest-standard 的技能包里（否则被过滤）。"""
    mode = load_mode("pentest-standard")
    allowed = set(mode.skills)
    for skill in SEED_SKILLS:
        assert skill.category in allowed, (
            f"{skill.id} 的类别 {skill.category!r} 不在 {sorted(allowed)} 里")


def test_seed_skills_have_actionable_steps():
    """技能要可执行：非空步骤 + 至少一个真实注册的工具名。"""
    for skill in SEED_SKILLS:
        assert len(skill.steps) >= 2, f"{skill.id} 步骤太少，等于没给指导"
        assert skill.tools, f"{skill.id} 未声明工具"
