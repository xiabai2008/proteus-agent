"""hack-skills 知识源集成回归（路线 1/2，2026-09-27）。

- tools/import_hack_skills.py：把 yaklang/hack-skills 选定技能蒸馏进
  内核技能库（<data>/skills/ctf-web/hs-*.json），幂等 upsert；
- 注入链路：Skill.category 须通过 ctf-web 模式技能包过滤
  （mode.skills = ["ctf-web"]），find_skills 按 target_fingerprint
  关键词共现命中。
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.memory import Memory, Skill
from tools.import_hack_skills import CURATED, import_skills


@pytest.fixture()
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    return d


def test_import_writes_curated_skills(data_dir):
    r = import_skills(str(data_dir))
    assert len(r["written"]) == len(CURATED)
    assert r["knowledge_source_missing"]          # 测试环境没克隆知识源
    for f in (data_dir / "skills" / "ctf-web").glob("hs-*.json"):
        skill = Skill.from_dict(json.loads(f.read_text(encoding="utf-8")))
        assert skill.title and skill.steps
        assert skill.category == "ctf-web"        # 模式技能包白名单要求


def test_import_is_idempotent_and_keeps_stats(data_dir):
    import_skills(str(data_dir))
    path = data_dir / "skills" / "ctf-web" / "hs-cmdi-command-injection.json"
    skill = Skill.from_dict(json.loads(path.read_text(encoding="utf-8")))
    skill.record_outcome(True)                    # 模拟一次复用成功
    path.write_text(json.dumps(skill.to_dict(), ensure_ascii=False),
                    encoding="utf-8")
    import_skills(str(data_dir))                  # 二次导入 = 更新
    reloaded = Skill.from_dict(json.loads(path.read_text(encoding="utf-8")))
    assert reloaded.attempts == 1 and reloaded.successes == 1


def test_imported_skills_pass_ctf_web_filter_and_match(data_dir):
    """注入链路端到端：导入后能被 ctf-web 模式过滤保留、按指纹命中。"""
    from penagent.modes import load_mode

    import_skills(str(data_dir))
    mem = Memory(str(data_dir), namespace="ctf-web")
    mode = load_mode("ctf-web")
    kept = [s for s in mem.list_skills()
            if not s.category or s.category in set(mode.skills)]
    hs = [s for s in kept if s.id.startswith("hs-")]
    assert len(hs) == len(CURATED)
    # 指纹命中：flask pickle 靶应命中反序列化技能
    hits = mem.find_skills("python web flask pickle deserialization 反序列化")
    assert any(s.id == "hs-deserialization-insecure" for s in hits)
