"""agent 驱动的真实靶场评测（评测骨架 · 方向 D 的下一步）。

与 `benchmark.py --suite lab` 的区别，一句话：

| 套件 | 谁决定探什么 | 回答的问题 |
|---|---|---|
| `lab`（已有） | 脚本（预定义路径清单） | 工具链对真实靶场可用吗 |
| `agent-lab`（本模块） | **agent 自己** | 这个 agent 强不强 |

判定不看 agent 的自述，也不看它写了多漂亮的总结，而是回到**证据链**：
预期发现的每一项，都必须在本次任务的 `tool_call` 记录里找到一次真实命中
（路径、状态码、可选内容标记均需对上），且**链校验必须通过**——链被改动
或指针断裂，该靶直接判失败。理由与反幻觉语义一致：结论必须由证据支撑，
而"探到了什么"这件事同样不能靠模型的口头汇报。

设计取向（与 `lab` 套件一致）：
- 靶不可达 / LLM 未配置 -> **skipped**，不进通过率分母。环境缺失不等于
  能力不足；
- 不管理容器生命周期，不 stop / rm 使用者的靶；
- 任务提示词**不列**预期路径清单——列了就变成脚本化的填空题，量不出
  自主侦察能力。agent 可以只探到一部分，评分卡如实记录探到了几项。

用法（经统一入口）：
    python examples/benchmark.py --suite agent-lab
    python examples/benchmark.py --suite agent-lab --out data/benchmark/agent.json
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "examples") not in sys.path:
    sys.path.insert(0, str(ROOT / "examples"))

DEFAULT_MAX_STEPS = 12          # 单靶决策步数上限（评测要控成本与时长）

# 侦察任务提示词：给目标与目标物，**不给路径清单**（见模块 docstring）
MISSION_TEMPLATE = (
    "对 {base} 做被动信息收集（授权范围内）。要求：\n"
    "1. 先确认首页可达并识别应用身份与技术栈；\n"
    "2. 自主枚举**常见的敏感路径与信息泄漏面**（配置/文档/目录列表/"
    "搜索引擎约定文件/REST 接口等），不要只探首页；\n"
    "3. 每条发现都要有工具输出的直接证据，不要凭猜测下结论；\n"
    "4. 只做 HTTP 探测类被动动作，不发送攻击载荷、不做爆破。\n"
    "完成后给出结论：可达端点清单 + 各自的状态码与证据。"
)


def mission_objective(base_url: str) -> str:
    return MISSION_TEMPLATE.format(base=base_url)


# ----------------------------------------------------------------------
# 判定：从证据链里核对预期发现（纯函数，可单测）
#
# 判定必须**与工具无关**：agent 用内置 `http_probe` 还是外部 `httpx_probe`
# 都算数——量的是"探到什么"，不是"用了哪个工具"。因此这里不按工具名过滤，
# 而是自己从输出里取状态码/跳转目标（两家的字段名不同：http_probe 出
# `status`、httpx 出 `status_code` 与 `location`，实测对比过）。
#
# 有状态码才算证据：爬虫列出一堆 URL 但没有状态码，不足以证明该端点可用，
# 不计命中（"观察到的"与"验证过的"必须分开）。
# ----------------------------------------------------------------------
_STATUS_RE = re.compile(
    r"['\"](?:status|status_code|status-code)['\"]\s*:\s*(\d{3})")
_HTTP_RE = re.compile(r"\bHTTP\s+(\d{3})\b")
_LOCATION_RE = re.compile(r"['\"]location['\"]\s*:\s*['\"]([^'\"]+)['\"]")


def _as_dict(text: Any) -> dict:
    """把工具输出还原成 dict（证据里存的是 str(output)，可能是 repr）。"""
    import ast

    if isinstance(text, dict):
        return text
    if not isinstance(text, str) or not text.strip():
        return {}
    try:
        parsed = json.loads(text)
    except Exception:                                     # noqa: BLE001
        try:
            parsed = ast.literal_eval(text)
        except Exception:                                 # noqa: BLE001
            return {}
    return parsed if isinstance(parsed, dict) else {}


def _urls_in(args: Any, payload: dict) -> list[str]:
    """收集这次调用涉及的 URL：参数里的 + 输出里回显的（含相对 path）。"""
    urls: list[str] = []
    if isinstance(args, dict):
        urls.extend(v for v in args.values()
                    if isinstance(v, str) and v.startswith("http"))
    for key in ("url", "input", "target"):
        value = payload.get(key)
        if isinstance(value, str) and value.startswith("http"):
            urls.append(value)
    path = payload.get("path")
    if isinstance(path, str) and path.startswith("/"):
        urls.append(path)          # 相对路径（httpx 的 path 字段）
    return urls


def _path_of(url: str) -> str:
    """取 URL 的路径部分（含 query）。

    接受的形态：绝对 URL、以 "/" 开头的路径、以及**相对跳转值**
    （`location: "login.php"` 这种——有基准 URL 时用 `_path_of_location`
    解析，这里只兜底取尾段）。
    """
    import urllib.parse

    if "://" not in url:
        if not url.startswith("/"):
            return "/" + url.split("?", 1)[0].lstrip("./")
        base = urllib.parse.urlsplit("http://placeholder" + url)
    else:
        base = urllib.parse.urlsplit(url)
    path = base.path or "/"
    return path + (f"?{base.query}" if base.query else "")


def _path_of_location(base_url: str, location: str) -> str:
    """解析跳转目标：相对值按基准 URL 拼接（`login.php` -> `/login.php`）。"""
    import urllib.parse

    if "://" in location:
        return _path_of(location)
    return _path_of(urllib.parse.urljoin(base_url, location))


def _path_matches(probed: str, expected: str) -> bool:
    """路径匹配：query 值可不同（agent 自选的 q= 值也算命中该端点）。"""
    probed_path = probed.split("?", 1)[0].rstrip("/") or "/"
    expected_path = expected.split("?", 1)[0].rstrip("/") or "/"
    return probed_path == expected_path


def _probes(records) -> list[dict]:
    """把成功的工具调用整理成"带状态码的探测"清单。"""
    out: list[dict] = []
    for rec in records:
        content = getattr(rec, "content", None) or {}
        if not content.get("ok"):
            continue
        blob = str(content.get("output", ""))
        payload = _as_dict(content.get("output"))
        status = None
        for key in ("status", "status_code", "status-code"):
            value = payload.get(key)
            if isinstance(value, int):
                status = value
                break
        if status is None:
            m = _STATUS_RE.search(blob) or _HTTP_RE.search(blob)
            if m:
                status = int(m.group(1))
        if status is None:
            continue                                  # 无状态码：不算探测证据
        location = payload.get("location") or ""
        if not location:
            m = _LOCATION_RE.search(blob)
            location = m.group(1) if m else ""
        for url in _urls_in(content.get("args"), payload):
            out.append({"tool": content.get("tool", ""), "url": url,
                        "path": _path_of(url), "status": int(status),
                        "location": str(location), "blob": blob})
    return out


def _satisfies(probe: dict, finding) -> bool:
    return (probe["status"] == finding.expect_status
            and (not finding.expect_contains
                 or finding.expect_contains in probe["blob"]))


def score_from_evidence(findings, records) -> dict[str, bool]:
    """逐项核对预期发现是否被**真实探测**过。

    命中条件（任一）：
    1. 探过该路径，状态码等于预期，且有标记时输出含该标记；
    2. 探过该路径得到 3xx，且**跳转目标也被探过并满足条件 1**——跟着重定向
       走到实际页面上同样算发现（DVWA 的 `/` 就是 302 到 `/login.php`，
       只认 200 会把"确认了首页归属"误判成没探到）。
    """
    probes = _probes(records)
    hits: dict[str, bool] = {}
    for f in findings:
        hit = False
        for p in probes:
            if not _path_matches(p["path"], f.path):
                continue
            if _satisfies(p, f):
                hit = True
                break
            if 300 <= p["status"] < 400 and p["location"]:
                target = _path_of_location(p["url"], p["location"])
                for q in probes:
                    if _path_matches(q["path"], target) and _satisfies(q, f):
                        hit = True
                        break
            if hit:
                break
        hits[f.name] = hit
    return hits


def probes_in(records) -> int:
    """本次任务里带状态码的探测次数（评分卡的"探了几次"）。"""
    return len(_probes(records))


# ----------------------------------------------------------------------
# agent 侧：按模式构建、下达任务
# ----------------------------------------------------------------------
def _build_agent(lab_id: str, workdir: Path, llm, max_steps: int):
    """构建打靶 agent：注册表按模式过滤，记忆/证据按靶隔离。"""
    from penagent.agent import PenAgent, Policy
    from penagent.evidence import EvidenceChain
    from penagent.memory import Memory
    from penagent.modes import load_mode
    from penagent.registry import build_center

    mode = load_mode("pentest-standard")
    registry = build_center().build_registry(mode=mode)
    base = workdir / lab_id
    memory = Memory(base / "mem")
    evidence = EvidenceChain(base / "chain.jsonl")
    policy = Policy(allowed_targets=["127.0.0.1", "localhost"],
                    authorize=True, mode=mode)
    agent = PenAgent(registry, memory, evidence, llm, policy=policy,
                     mode=mode, max_steps=max_steps)
    return agent, evidence


def run_lab_agent(lab, base_url: str, workdir: Path, llm,
                  max_steps: int = DEFAULT_MAX_STEPS,
                  seed: bool = False) -> dict:
    """让 agent 自主跑一次该靶的侦察任务，返回原始素材（不判分）。

    调用方拿 `records` 与 `chain` 自己判分——判分逻辑与执行逻辑分开，
    判分可被单测覆盖、可被复算。

    `seed=True` 时先把 `penagent/skill_seeds.py` 的预置技能写进本靶记忆库
    （幂等）——这是"技能注入 -> 评测验证收益"的开关。**写入的是 agent
    实际读取的那个 memory 对象**（带模式 namespace）：`Memory(root)` 与
    `Memory(root).for_namespace(模式)` 是两个目录，写错地方不会报错、
    只会静默不生效。

    指纹走上产口径（CLI 的 `_auto_fingerprint`：`<host> web service`），
    不用裸 URL：技能匹配是关键词共现，裸 URL 只剩 "http" 一个词，
    匹配几乎无区分度。记忆库里没有技能时指纹不影响行为，故改变它不破坏
    与历史轮次的可比性。
    """
    import urllib.parse

    agent, evidence = _build_agent(lab.id, workdir, llm, max_steps)
    if seed:
        from penagent.skill_seeds import seed_skills

        # refresh=True：评测记忆是测量沙箱，测的是"当前这版知识"——
        # 种子文件迭代后重测必须拿到新正文（学习统计保留，见 seed_skills）
        seed_skills(agent.memory, refresh=True)
    host = urllib.parse.urlsplit(base_url).hostname or base_url
    start_seq = (evidence.tail().seq if evidence.tail() else 0)
    started = time.time()
    result = agent.run(base_url, mission_objective(base_url),
                       fingerprint=f"{host} web service")
    records = [r for r in evidence.load() if r.seq > start_seq]
    return {
        "outcome": result.outcome,
        "steps": result.steps,
        "summary": str(result.summary)[:200],
        "elapsed_s": round(time.time() - started, 2),
        "records": records,
        "chain": evidence.verify(),
        "mission_id": result.mission_id,
        "injected_skills": list(result.injected_skills),
    }


# ----------------------------------------------------------------------
# 套件入口（供 examples/benchmark.py 注册）
# ----------------------------------------------------------------------
def run_agent_lab_suite(root: Path, driver: str = "agent",
                        max_steps: int = DEFAULT_MAX_STEPS,
                        labs: Optional[list[str]] = None,
                        seed: bool = False):
    """agent 驱动的真实靶场评测套件。

    靶不可达 / LLM 未配置 -> skipped（环境缺失不等于能力不足）。
    `seed=True` 时按靶写入预置技能（见 `run_lab_agent`）。
    """
    from benchmark import CaseResult          # 统一结果模型
    from lab import DEFAULT_URLS, LABS, reachable

    def _skipped(case_id: str, why: str) -> "CaseResult":
        return CaseResult(suite="agent-lab", case_id=case_id,
                          category="recon-agent", outcome="skipped",
                          passed=False, detail=why)

    from penagent.llm import LLMConfig

    llm = LLMConfig.from_env()
    if not llm.ready():
        return [_skipped(lab.id, "LLM 未配置（设 PENTEST_LLM_* 后可用）")
                for lab in LABS if not labs or lab.id in labs]

    results = []
    # root 就是本套件自己的工作目录（与 run_ctf_suite 等同约定，不再套一层）
    workdir = Path(root)
    for lab in LABS:
        if labs and lab.id not in labs:
            continue
        base_url = DEFAULT_URLS.get(lab.id, "")
        if not base_url or not reachable(base_url):
            results.append(_skipped(lab.id, f"靶不可达（{lab.hint}）"))
            continue
        # 真实运行是分钟级的，先给出"正在打哪个靶"——否则使用方看不到进展
        print(f"[agent-lab] {lab.id} <- {base_url}（上限 {max_steps} 步"
              f"{'，已注入预置技能' if seed else ''}）", flush=True)
        started = time.time()
        try:
            run = run_lab_agent(lab, base_url, workdir, llm,
                                max_steps=max_steps, seed=seed)
        except Exception as exc:                          # noqa: BLE001
            results.append(CaseResult(
                suite="agent-lab", case_id=lab.id, category="recon-agent",
                outcome="failed", passed=False,
                elapsed_s=round(time.time() - started, 2),
                detail=f"{type(exc).__name__}: {exc}"))
            continue
        print(f"[agent-lab] {lab.id} 完成：steps={run['steps']} "
              f"{run['elapsed_s']}s outcome={run['outcome']}", flush=True)
        # 原始素材落盘：判分口径之外的东西（探过哪些路径、报了什么错）以后
        # 复盘时最常被问起，不留就只能翻证据链猜任务边界
        try:
            _save_raw(run, workdir / lab.id / "last_run.json")
        except OSError as exc:                            # noqa: PERF203
            print(f"[agent-lab] 原始素材落盘失败（不判失败）: {exc}",
                  flush=True)

        hits = score_from_evidence(lab.findings, run["records"])
        matched = sum(1 for v in hits.values() if v)
        total = len(hits)
        chain_ok = bool(run["chain"].get("ok"))
        passed = bool(total) and matched == total and chain_ok
        missed = [k for k, v in hits.items() if not v]
        why = ""
        if not chain_ok:
            why = (f"证据链校验失败（tampered={run['chain'].get('tampered')} "
                   f"broken={run['chain'].get('broken_links')}）")
        elif missed:
            why = f"未探到: {', '.join(missed)}"
        results.append(CaseResult(
            suite="agent-lab", case_id=lab.id, category="recon-agent",
            outcome="success" if passed else "failed", passed=passed,
            steps=run["steps"], elapsed_s=run["elapsed_s"],
            expected=f"{total} 项预期发现（agent 自主侦察）",
            got=f"{matched}/{total} 命中 · 探测 {probes_in(run['records'])} 次"
                f" · agent outcome={run['outcome']}"
                f" · 注入技能 {len(run.get('injected_skills') or [])} 条",
            detail=why))
    return results


def _save_raw(run: dict, path: Path) -> None:
    """把一次 agent 运行的原始素材落盘（复盘用，不含判分口径）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "outcome": run["outcome"], "steps": run["steps"],
        "summary": run["summary"], "chain": run["chain"],
        "records": [r.to_dict() for r in run["records"]],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
