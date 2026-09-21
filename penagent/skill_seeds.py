"""预置技能种子：把"评测里量出来的能力缺口"固化成可复用的技能。

为什么单独放一个文件，而不是写在评测脚本里：技能是**产品知识**——种子一旦
写进某个 agent 的记忆库，之后每一次运行（CLI / MCP / 评测）都会命中它。
只写在评测里等于只有评测受益。

两条种子的来源都是**实测**（不是凭空总结的行话）：

- `web-api-family-enum`：2026-09-21 agent-lab 第二轮打 Juice Shop 时，agent
  探了 `/rest` 与 `/api`（都 500）就整族放弃，漏掉 `/rest/products/search?q=`、
  `/api/Challenges`、`/rest/admin/application-version`（该轮 6/10，证据见
  `data/benchmark/agent-lab/juice-shop/last_run.json`）；
- `web-dir-listing-enum`：同一轮里它拿到了 `/ftp` 的目录列表，却只探了
  `package.json.bak`，漏掉列表里已经列出来的 `acquisitions.md`。

与 `reflect.py` 从任务里自动提炼的技能的区别：这两条是**人工写定**的，
所以 `evidence_refs` 为空、来源写在 `evidence_text` 里（自动提炼的技能则
必须有证据引用，见 `reflect.py` 的"无证据不进库"）。

用法：
    from penagent.memory import Memory
    from penagent.skill_seeds import seed_skills

    seed_skills(Memory("data"))         # 幂等：已存在的 id 跳过

    python -m penagent skills --seed    # 命令行等价入口
"""
from __future__ import annotations

from .memory import Memory, Skill

# 类别必须落在模式声明的技能包里，否则会被 PenAgent._filter_mode_skills
# 机制性过滤掉（pentest-standard 声明 web-recon / sqli / ssrf / report-gen）。
# 指纹用关键词，与目标指纹做共现匹配：CLI 的自动指纹形如
# "<host> web service"，故这里带 web / service 关键词。
SEED_SKILLS: tuple[Skill, ...] = (
    Skill(
        id="web-api-family-enum",
        title="Web 端点族枚举：按通用资源名词表铺开，父路径 5xx 不代表子路径不存在",
        target_fingerprint="web service http rest api endpoint",
        category="web-recon",
        steps=[
            "**先横后纵**：先把各族常见子路径一次铺开，再回头对单点深挖",
            "**用通用资源名词表枚举，不要只探别人点名过的那几个**：对已发现"
            "的 API 前缀（/api、/rest）逐个试 products、orders、users、"
            "feedbacks、reviews、challenges、quantitys、security-questions、"
            "languages、basket、deliveries、memories、complaints、banners、"
            "config 等常见资源名——同一前缀下的接口往往成套出现",
            "父路径（/api、/rest 等）返回 4xx/5xx 时不要放弃整族——子路径"
            "可能独立可达（实测 /api 与 /rest 本身 500，其下子路径却大量 200）",
            "401/403 同样是有效发现（接口存在、需鉴权或禁访），按状态码如实"
            "记录，不要因为读不到内容就丢弃",
            "步数有限：横向铺开的收益高于对单一目录/单点的反复深挖",
            "**收口前做覆盖自检**：把「计划覆盖的面」（各族子路径、目录里的"
            "高风险项）与「已探过的清单」对一遍，缺口先补上再收口——觉得"
            "「差不多了」就收口，是最常见的漏项来源",
        ],
        tools=["http_probe", "http_raw", "httpx_probe"],
        evidence_text="来源：2026-09-21 agent-lab 第二轮（juice-shop）——探过 "
                      "/rest 与 /api（均 500）后整族放弃，漏掉 "
                      "/rest/products/search?q=、/api/Challenges、"
                      "/rest/admin/application-version（该轮 6/10）；"
                      "第三轮加'先横后纵'后 10/10，但第四轮实测暴露**清单驱动**"
                      "的局限：技能里点名的子路径全探到了，通用资源名的接口"
                      "（/api/Feedbacks、/api/Quantitys、/rest/languages，均 200）"
                      "一个没试——故改写为'按通用资源名词表铺开'的方法式指导；"
                      "第四轮三轮复测（10/10、8/10、7/10）显示漏项与**提前收口**"
                      "相关（分别停在 20/15/11 步，/api/Users 连续两轮没探），"
                      "故补'收口前覆盖自检'",
    ),
    Skill(
        id="web-dir-listing-enum",
        title="目录列表到手后按高风险类型限量枚举",
        target_fingerprint="web service http directory listing index of",
        category="web-recon",
        steps=[
            "探到目录列表（标题含 'Index of' 或 'listing directory'）说明该目录"
            "可列——**先挑高风险的前 5 个**探：*.md 文档、*.bak / *.old / *.dist "
            "备份、package.json、配置文件",
            "不要把列表逐个探完再换目标：长列表会把步数预算吃光，而横向"
            "铺开（其它接口族）的收益更高；剩余项记进结论即可",
            "目录列表本身是一条发现（信息泄漏），结论里写明它暴露了什么",
        ],
        tools=["http_probe", "http_raw", "httpx_probe"],
        evidence_text="来源：2026-09-21 agent-lab 第二轮（juice-shop）——拿到 "
                      "/ftp 目录列表后只探了 package.json.bak，漏掉列表里"
                      "已列出的 acquisitions.md；第三轮加了'逐项枚举'后反向"
                      "踩坑：13 个文件逐个探完，20 步里 13 步耗在 /ftp，"
                      "REST 族一个没试（该轮 4/10）——故改为限量 + 先横后纵",
    ),
    Skill(
        id="web-catchall-discriminate",
        title="SPA 兜底页甄别：路径都返回 200 时先证明它不是兜底",
        target_fingerprint="web service http spa catchall fallback",
        category="web-recon",
        steps=[
            "若干互不相干的路径都返回 200、且标题与正文都跟应用首页一样时，"
            "**先怀疑是 SPA / 兜底页**，而不是一口气记成一堆发现",
            "判据：探一个几乎不可能存在的随机路径（如 "
            "/no-such-path-<随机串>）——若它同样 200 且响应体与"
            "'疑似发现'一致，那些 200 就没有信息量",
            "真发现的判据是**响应内容随路径变化**（内容类型/长度/正文不同，"
            "如 application/json vs text/html），或状态码有区分（401/403/500）",
            "结论里只写经对照验证过的路径；把兜底页当发现写进报告等于污染"
            "结论的可信度",
        ],
        tools=["http_probe", "http_raw", "httpx_probe"],
        evidence_text="来源：2026-09-21 agent-lab 第三轮 B（juice-shop）——"
                      "agent 把 /.git/config 的 200 当真实信息泄漏写进结论；"
                      "实测它与不存在路径 /no-such-path-xyz 返回的是同一份 "
                      "index.html（text/html），而同轮的 /api/Feedbacks 返回 "
                      "application/json 才是真接口",
    ),
)


def seed_skills(memory: Memory, refresh: bool = False) -> dict:
    """把预置技能写进记忆库。

    默认**幂等**：已存在的 id 跳过，不覆盖——技能被复用后会回写
    `success_rate` / `attempts`（`Skill.record_outcome`），种子再跑一次
    不该把这些统计抹掉。

    `refresh=True` 用于"知识迭代 -> 重新验证"的闭环：**用种子的新定义覆盖
    技能正文**（步骤/工具/指纹/来源说明），但**保留学习统计**（成功率、
    成功/尝试次数、创建时间）——否则每改一版种子就把历史成绩清零，
    策略侧（Q 学习 / PPO 的技能排序）会失去依据。

    评测侧固定用 refresh=True（评测记忆是测量沙箱，要的是"当前这版知识"）；
    用户侧用 CLI 显式 `--refresh`（默认不动已学到的技能）。
    """
    existing = {s.id: s for s in memory.list_skills()}
    added, refreshed, skipped = [], [], []
    for skill in SEED_SKILLS:
        old = existing.get(skill.id)
        if old is None:
            # 深拷贝一份再入库：SEED_SKILLS 是模块级常量，add_skill 会写
            # created_at 等运行时字段，直接入库会污染常量
            memory.add_skill(Skill.from_dict(skill.to_dict()))
            added.append(skill.id)
            continue
        if not refresh:
            skipped.append(skill.id)
            continue
        merged = Skill.from_dict(skill.to_dict())
        merged.successes = old.successes
        merged.attempts = old.attempts
        merged.success_rate = old.success_rate
        merged.created_at = old.created_at or merged.created_at
        memory.update_skill(merged)
        refreshed.append(skill.id)
    return {"added": added, "refreshed": refreshed, "skipped": skipped}
