"""把 yaklang/hack-skills 的选定技能蒸馏进内核技能库（路线 2 第一批）。

来源库：data/knowledge/hack-skills（yaklang/hack-skills 浅克隆，102+ 技能，
主入口→分类入口→深度技能三层）。本脚本不做全文搬运——每个入选技能由
人工蒸馏成内核 Skill 记录（中文步骤、内核工具名、指纹关键词），并留
`evidence_text` 指回原文 SKILL.md 供 agent 按需深读（路线 1 的知识源）。

为什么手工蒸馏而不是脚本全文导入（2026-09-27 决策）：
- find_skills 按 target_fingerprint 关键词共现匹配——指纹要对着内核调用
  方式写（中文+英文混合），机器搬运写不出这种粒度；
- pentest_run 的系统提示只注入排序后前 3 条——条目必须小而准，全文塞进
  steps 会把预算烧在上下文里；
- deep topic SKILL.md 仍在知识源里，evidence_text 指路即可，按需深读。

用法：
    python tools/import_hack_skills.py [--data-dir data]
幂等：同 id 覆盖（Skill 落盘为 <id>.json，重复导入=更新）。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from penagent.memory import Skill  # noqa: E402

# 知识源相对 data_dir 的路径（路线 1 的克隆位置）
KNOWLEDGE_REL = "knowledge/hack-skills/skills"

# 第一批：CTF Web 高频六个方向（每条步骤都对应内核工具可执行的动作；
# 深层 payload 细节不进 steps——evidence_text 指向原文按需读）
CURATED = [
    {
        "slug": "deserialization-insecure",
        "title": "反序列化 RCE 系统化打法（PHP/Python/Java）",
        "category": "ctf-web",
        "fingerprint": "反序列化 deserialize unserialize pickle yaml php "
                       "java python web flask",
        "steps": [
            "指纹判型：报错/响应头/入口参数形态判断语言与库（PHP unserialize、"
            "Python pickle/base64 gASV 前缀、YAML !!python、Java AC ED 00 05）",
            "PHP：先确认是否有可用 gadget（composer 阅读/vendor 目录枚举），"
            "按 魔术方法入口（__destruct/__wakeup/__toString）链到执行原语；"
            "无链时测 phar:// 流包装",
            "Python pickle：http_raw 确认回显与否——有回显直接 check_output；"
            "零回显走 oob_read 外带或写文件三步（见人格第 8 条）",
            "YAML：pyyaml unsafe_load 用 !!python/object/apply:os.system；"
            "safe_load 出现 !!python 即确认误配",
            "结论用 replay_request 重放确认可复现，report_gen 收口",
        ],
        "tools": ["http_raw", "python_solve", "oob_read", "replay_request",
                  "report_gen"],
    },
    {
        "slug": "ssti-server-side-template-injection",
        "title": "SSTI 引擎判型与利用（Jinja2/Twig/Freemarker 等）",
        "category": "ctf-web",
        "fingerprint": "ssti template injection jinja2 twig 模板注入 "
                       "python web flask",
        "steps": [
            "探针判型：{{7*7}}/${7*7}/<%= 7*7 %> 差异化注入定位引擎家族",
            "Jinja2：{{lipsum.__globals__['os'].popen('id').read()}} 类 "
            "lipsum/配置对象 gadget 拿执行原语；waf 时按字符集做字符串拼接",
            "零回显时绑执行原语到 oob_read 外带或写文件到已知可读路由",
            "replay_request 确认可复现后 report_gen 收口",
        ],
        "tools": ["http_raw", "python_solve", "oob_read", "replay_request",
                  "report_gen"],
    },
    {
        "slug": "sqli-sql-injection",
        "title": "SQL 注入判型与无回显利用（登录态/布尔/时间盲注）",
        "category": "ctf-web",
        "fingerprint": "sql injection sqli mysql sqlite 登录 login "
                       "authentication bypass sql",
        "steps": [
            "判型：报错注入（直接回显错误）→ 联合查询（列数对齐）→ "
            "布尔/时间盲注（响应差异或 SLEEP 延迟）依次排除",
            "登录态绕过：admin'-- 类注释闭合、OR 1=1 恒真；用 session_http "
            "带 cookie 验证登录后路径",
            "盲注用 python_solve 写二分脚本逐字符提取（内核侧跑，别手数）",
            "SQLite/MySQL 特性差异按知识源原文核（attach/写文件路径不同）",
            "replay_request 固化 PoC 请求，report_gen 收口",
        ],
        "tools": ["http_raw", "session_http", "python_solve", "replay_request",
                  "report_gen"],
    },
    {
        "slug": "cmdi-command-injection",
        "title": "命令注入绕过与执行确认",
        "category": "ctf-web",
        "fingerprint": "command injection cmdi rce exec shell 命令注入 "
                       "ping host web",
        "steps": [
            "确认拼接点：原参数后接 ; | ` $( ) 换行等分隔符逐个试",
            "过滤绕过：空格用 ${IFS}/$IFS$9，关键词用 ca\\t / 变量拼接，"
            "编码用 base64 管道解码执行",
            "读 flag：cat /flag* 或 ls / 先定位；输出进不了响应时改 "
            "oob_read 外带或写到 Web 根",
            "replay_request 重放确认，report_gen 收口",
        ],
        "tools": ["http_raw", "oob_read", "replay_request", "report_gen"],
    },
    {
        "slug": "ssrf-server-side-request-forgery",
        "title": "SSRF 利用面与协议升级（gopher/file/云元数据）",
        "category": "ctf-web",
        "fingerprint": "ssrf request forgery 内网 url fetch proxy "
                       "ssrf web curl",
        "steps": [
            "确认回连点：url/file/fetch 类参数，先用 http_probe 打宿主端口 "
            "验证服务器代请求是否成立",
            "协议面：file:/// 读本地、gopher:// 打内网 Redis/HTTP、"
            "http://host.docker.internal 打宿主（容器内视角同 oob_read 提示）",
            "盲 SSRF 直接接 oob_read：让目标回连收集器即证明确认",
            "内网横向时记录端口差异，证据链留痕后 report_gen 收口",
        ],
        "tools": ["http_raw", "http_probe", "oob_read", "report_gen"],
    },
    {
        "slug": "path-traversal-lfi",
        "title": "路径穿越与 LFI-to-RCE（wrapper 矩阵）",
        "category": "ctf-web",
        "fingerprint": "lfi path traversal 文件包含 include readfile "
                       "wrapper php web",
        "steps": [
            "穿越深度 ../ 递增或绝对路径直读；过滤绕过：....//、编码 %2e%2e、"
            "PHP filter 链",
            "PHP wrapper 矩阵：php://filter/convert.base64-encode 读源码，"
            "data:// 与 input:// 直接执行（需 allow_url_include）",
            "LFI-to-RCE：日志投毒（session 上传进度/-access.log）、"
            "php://filter chain 爆破生成执行型 filter（见知识源原文）",
            "读到的源码用 python_solve 解码判读，结论 report_gen 收口",
        ],
        "tools": ["http_raw", "python_solve", "report_gen"],
    },
]


def import_skills(data_dir: str, knowledge_rel: str = KNOWLEDGE_REL) -> dict:
    """把 CURATED 蒸馏技能 upsert 进 <data_dir>/skills/ctf-web/。"""
    skills_dir = Path(data_dir) / "skills" / "ctf-web"
    skills_dir.mkdir(parents=True, exist_ok=True)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    written, src_missing = [], []
    for entry in CURATED:
        skill_id = ("hs-" + entry["slug"])[:40]
        src = Path(data_dir) / knowledge_rel / entry["slug"] / "SKILL.md"
        skill = Skill(
            id=skill_id,
            title=entry["title"],
            target_fingerprint=entry["fingerprint"],
            steps=entry["steps"],
            tools=entry["tools"],
            evidence_text=(
                f"延伸阅读: {src.as_posix()}"
                + ("" if src.is_file() else "（知识源未克隆，路径供参考）")),
            category=entry["category"],
            source_mission="hack-skills-import",
            created_at=now,
        )
        # 已存在则保留复用统计（成功率/次数），其余字段以本批蒸馏为准
        existing = skills_dir / f"{skill_id}.json"
        if existing.is_file():
            try:
                old = Skill.from_dict(json.loads(existing.read_text("utf-8")))
                skill.success_rate = old.success_rate
                skill.successes = old.successes
                skill.attempts = old.attempts
            except (OSError, ValueError, TypeError):
                pass
        existing.write_text(json.dumps(skill.to_dict(), ensure_ascii=False,
                                       indent=2), encoding="utf-8")
        written.append(skill_id)
        if not src.is_file():
            src_missing.append(entry["slug"])
    return {"written": written, "knowledge_source_missing": src_missing}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", default=str(PROJECT_ROOT / "data"))
    args = ap.parse_args()
    result = import_skills(args.data_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
