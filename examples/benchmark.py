"""统一评测骨架（能力加强路线 · 方向 D）。

背景：仓库里已有 5 个 `eval_*.py`，各测一面，但缺三样东西——

  ① 统一入口：没有"跑一遍看总分"的地方，五个脚本要分别记命令与参数
  ② 统一结果模型：每个脚本的指标词汇不同（步数 / 成功率 / 加权收益），
     结果只打印到 stdout，无法落盘、无法跨版本比对
  ③ 统一评分卡：解出率 / 平均步数 / 耗时 / 失败原因不可一眼看全

本模块补这三样，**不重造已有 suite**：各 suite 只负责"怎么跑一批"，
结果的收集、聚合、落盘、对比统一在这里。

为什么这件事最重要：仓库现有 239 个测试**全部在测机制**（模式裁决、闸门、
沙箱、判定器），能回答"机制正确吗"，不能回答"这个 agent 强不强"。
没有能力度量，任何能力投入都无法判断是否变好。

用法：
    python examples/benchmark.py --suite ctf                 # 离线确定性
    python examples/benchmark.py --suite pentest             # 起本地授权靶
    python examples/benchmark.py --suite all --out data/benchmark/run.json
    python examples/benchmark.py --compare data/benchmark/baseline.json

结果文件落 `data/benchmark/*.json`（data/ 已 gitignore，属运行时产物）。
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

# 输出编码兜底：CI（cp1252 控制台）下打印中文会 UnicodeEncodeError——
# 与启动器输出编码兜底同一策略（2026-09-23 被 windows CI 抓到）。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = Path(__file__).resolve().parent.parent
# 内核包在仓库根下，脚本从 examples/ 运行时要显式加入 import 路径
sys.path.insert(0, str(ROOT))

DEFAULT_OUT = ROOT / "data" / "benchmark"


# ----------------------------------------------------------------------
# 统一结果模型
# ----------------------------------------------------------------------
@dataclass
class CaseResult:
    """一次评测用例的结果（无论 suite 是什么，形状一致）。"""

    suite: str
    case_id: str
    category: str = ""
    outcome: str = "failed"        # success | failed | skipped
    passed: bool = False
    steps: int = 0
    elapsed_s: float = 0.0
    expected: str = ""             # 期望结果（flag / 预期发现摘要）
    got: str = ""                  # 实际拿到什么
    detail: str = ""               # 失败原因或补充说明
    # P2-2 分档评分（仅 CTF 套件用；其他套件留空 = 不参与）
    subtask: str = ""              # 里程碑完成比例，如 "2/3"（"" = 无分档）
    subtask_score: float = 0.0     # 0..1
    subtask_guided: bool = False   # 只看最后一个里程碑（= flag 收口）

    @property
    def skipped(self) -> bool:
        return self.outcome == "skipped"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Scorecard:
    """一次完整评测的评分卡（可落盘、可比对）。"""

    driver: str = "scripted"
    started_at: str = ""
    results: list[CaseResult] = field(default_factory=list)

    # ---------------- 聚合 ----------------
    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.skipped)

    @property
    def attempted(self) -> int:
        """实际跑了用例数（排除 skipped）——分母。"""
        return self.total - self.skipped

    @property
    def pass_rate(self) -> float:
        return self.passed / self.attempted if self.attempted else 0.0

    @property
    def avg_steps(self) -> float:
        stepped = [r.steps for r in self.results
                   if not r.skipped and r.steps]
        return sum(stepped) / len(stepped) if stepped else 0.0

    @property
    def total_elapsed_s(self) -> float:
        return sum(r.elapsed_s for r in self.results)

    def by_category(self) -> dict[str, dict]:
        """按 category 分组统计（用于看"哪一类弱"）。"""
        groups: dict[str, list[CaseResult]] = {}
        for r in self.results:
            groups.setdefault(r.category or "未分类", []).append(r)
        out = {}
        for cat, items in sorted(groups.items()):
            attempted = [i for i in items if not i.skipped]
            out[cat] = {
                "total": len(items),
                "passed": sum(1 for i in items if i.passed),
                "attempted": len(attempted),
                "pass_rate": (sum(1 for i in items if i.passed) / len(attempted)
                              if attempted else 0.0),
            }
        return out

    def failures(self) -> list[CaseResult]:
        return [r for r in self.results if not r.passed and not r.skipped]

    # ---------------- 序列化 ----------------
    def to_dict(self) -> dict:
        return {
            "driver": self.driver,
            "started_at": self.started_at,
            "summary": {
                "total": self.total,
                "passed": self.passed,
                "skipped": self.skipped,
                "attempted": self.attempted,
                "pass_rate": round(self.pass_rate, 4),
                "avg_steps": round(self.avg_steps, 2),
                "total_elapsed_s": round(self.total_elapsed_s, 2),
            },
            "by_category": self.by_category(),
            "results": [r.to_dict() for r in self.results],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Scorecard":
        card = cls(driver=data.get("driver", ""),
                   started_at=data.get("started_at", ""))
        card.results = [
            CaseResult(**{k: v for k, v in item.items()
                          if k in CaseResult.__dataclass_fields__})
            for item in data.get("results", [])]
        return card

    # ---------------- 跨版本对比 ----------------
    def compare(self, baseline: "Scorecard") -> dict:
        """与基线对比：整体通过率变化 + 逐个用例的变化方向。

        逐例对比是这里最有价值的部分——只看总分会被"这题好了那题坏了"
        相互抵消掩盖。
        """
        base_by_id = {f"{r.suite}/{r.case_id}": r for r in baseline.results}
        fixed, regressed, unchanged = [], [], []
        for r in self.results:
            key = f"{r.suite}/{r.case_id}"
            old = base_by_id.get(key)
            if old is None:
                unchanged.append(key)      # 基线里没有：不计入回归
                continue
            if r.passed and not old.passed:
                fixed.append(key)
            elif old.passed and not r.passed:
                regressed.append(key)
            else:
                unchanged.append(key)
        return {
            "baseline_started_at": baseline.started_at,
            "pass_rate": {"before": round(baseline.pass_rate, 4),
                          "after": round(self.pass_rate, 4),
                          "delta": round(self.pass_rate - baseline.pass_rate, 4)},
            "avg_steps": {"before": round(baseline.avg_steps, 2),
                          "after": round(self.avg_steps, 2),
                          "delta": round(self.avg_steps - baseline.avg_steps, 2)},
            "fixed": sorted(fixed),
            "regressed": sorted(regressed),
            "unchanged_count": len(unchanged),
        }

    # ---------------- 呈现 ----------------
    def render(self) -> str:
        lines = [
            "=" * 68,
            f"评分卡 · driver={self.driver} · {self.started_at}",
            "=" * 68,
        ]
        for r in self.results:
            mark = "PASS" if r.passed else ("SKIP" if r.skipped else "FAIL")
            detail = f" | {r.detail}" if r.detail and not r.passed else ""
            lines.append(f"  [{mark}] {r.suite}/{r.case_id:<24} "
                         f"steps={r.steps} {r.elapsed_s:.1f}s{detail}")
        lines.append("-" * 68)
        lines.append(f"  通过 {self.passed}/{self.attempted}"
                     f"（跳过 {self.skipped}）"
                     f" · 通过率 {self.pass_rate:.0%}"
                     f" · 平均步数 {self.avg_steps:.1f}"
                     f" · 总耗时 {self.total_elapsed_s:.1f}s")
        # P2-2 分档：里程碑完成比例（"差多少"），与二值通过率并列
        graded = [r for r in self.results if r.subtask]
        if graded:
            score = sum(r.subtask_score for r in graded) / len(graded)
            full = sum(1 for r in graded if r.subtask_score >= 1.0)
            guided = sum(1 for r in graded if r.subtask_guided)
            lines.append(f"  分档（{len(graded)} 题）里程碑均值 {score:.0%}"
                         f" · 里程碑全完成 {full}/{len(graded)}"
                         f" · 收口（末条里程碑）{guided}/{len(graded)}")
            lagging = sorted((r for r in graded if r.subtask_score < 1.0),
                             key=lambda r: r.subtask_score)
            for r in lagging[:5]:
                lines.append(f"    {r.case_id:<24} {r.subtask}"
                             f"（差在最后一步：{r.detail[:40] or '见里程碑'}）")
        for cat, stat in self.by_category().items():
            lines.append(f"    {cat:<20} {stat['passed']}/{stat['attempted']}"
                         f" ({stat['pass_rate']:.0%})")
        lines.append("=" * 68)
        return "\n".join(lines)


# ----------------------------------------------------------------------
# Suite 实现
# ----------------------------------------------------------------------
def run_ctf_suite(root: Path, driver: str = "scripted",
                  cases: Optional[list[str]] = None) -> list[CaseResult]:
    """CTF 解题套件：复用 eval_ctf_solve 的三道离线题（脚本化决策 + 真实工具）。

    driver=llm 时改用真实 LLM 决策（需 PENTEST_LLM_* 配置），本函数只做
    结果标准化；LLM 通道的完整实现见 eval_evolution_llm.py 的模式。
    """
    import sys

    examples = ROOT / "examples"
    if str(examples) not in sys.path:
        sys.path.insert(0, str(examples))
    from eval_ctf_solve import build_challenges, solve_graded  # noqa: E402

    root = Path(root)
    challenges = build_challenges(root)
    results: list[CaseResult] = []
    for cid, meta in challenges.items():
        if cases and cid not in cases:
            continue
        # 类别由题集自带（encoding / stego / crypto），不从 id 前缀猜
        category = str(meta.get("category", "") or "")
        started = time.time()
        try:
            out = solve_graded(root, cid, meta, mode_id="ctf-crypto")
            result, grade = out["result"], out["grade"]
            elapsed = time.time() - started
            got = meta["flag"] if meta["flag"] in str(result.summary) else ""
            results.append(CaseResult(
                suite="ctf", case_id=cid, category=category,
                outcome=result.outcome,
                passed=(result.outcome == "success"),
                steps=result.steps, elapsed_s=round(elapsed, 2),
                expected=meta["flag"], got=got or str(result.summary)[:80],
                detail="" if result.outcome == "success" else result.summary[:80],
                # P2-2：分档（里程碑由题集真值派生，判据落在工具输出上）
                subtask=grade["subtask"],
                subtask_score=grade["subtask_score"],
                subtask_guided=grade["subtask_guided"],
            ))
        except Exception as exc:                          # noqa: BLE001
            results.append(CaseResult(
                suite="ctf", case_id=cid, category=category,
                outcome="failed", passed=False,
                elapsed_s=round(time.time() - started, 2),
                expected=meta["flag"], detail=f"{type(exc).__name__}: {exc}"))
    return results


# 渗透侦察套件：演示靶（examples/target.py）的预期发现。
#
# 判定必须落在**响应内容**上——早期版本用子串匹配整段 JSON，结果 `"server"`
# / `"title"` / `"disallow"` 这类**键名**恒真（http_probe 的返回 dict 永远含
# 这些键）、`"/debug"` 命中的是 URL 字段——四条断言里三条恒真，套件必然 100%。
# 现在改成逐项结构化判定（状态码/字段值/真实指纹）。
PENTEST_HOME_TITLE = "Demo Portal"     # 演示靶首页标题里的真实指纹


def run_pentest_suite(root: Path, driver: str = "scripted",
                      target: str = "127.0.0.1",
                      port: int = 8090) -> list[CaseResult]:
    """渗透侦察套件：对本地授权演示靶跑一次侦察，逐项断言预期发现。

    默认端口 **8090** 而非 8080：本机 8080 常被真实靶场（DVWA）占用，
    套件不该打到别人的靶上。

    靶子不可达时**标记 skipped 而不是 failed**——环境缺失不等于能力不足，
    这条区分很重要（否则"没起靶"会被误读成"agent 不行"）。
    """
    started = time.time()
    if not _port_open(target, port):
        return [CaseResult(
            suite="pentest", case_id="local-portal-recon", category="recon",
            outcome="skipped", passed=False,
            detail=f"靶子 {target}:{port} 不可达（先跑 "
                   f"python examples/target.py --port {port}）")]

    findings = _pentest_findings(target, port)
    matched = [name for name, ok in findings.items() if ok]
    required = len(findings)
    passed = len(matched) == required
    missed = [k for k, v in findings.items() if not v]
    return [CaseResult(
        suite="pentest", case_id="local-portal-recon", category="recon",
        outcome="success" if passed else "failed", passed=passed,
        steps=len(matched), elapsed_s=round(time.time() - started, 2),
        expected=f"{required} 项预期发现全命中",
        got=f"{len(matched)}/{required}",
        detail="" if passed else f"未命中: {', '.join(missed)}",
    )]


def _port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


def _probe_target(host: str, port: int) -> dict:
    """对演示靶做被动侦察，返回结构化探测结果。

    只用内核内置工具（零外部依赖），不引入攻击动作。
    """
    from penagent.builtin_tools import http_probe, robots_fetch

    base = f"http://{host}:{port}"
    return {
        "home": http_probe(base),
        "admin": http_probe(f"{base}/admin"),
        "debug": http_probe(f"{base}/debug"),
        "robots": robots_fetch(base),
    }


def _pentest_findings(host: str, port: int) -> dict:
    """逐项判定预期发现（每条断言都落在响应内容上）。"""
    probes = _probe_target(host, port)
    return {
        "home_reachable": probes["home"].get("status") == 200,
        "admin_protected": probes["admin"].get("status") == 401,
        "debug_leak": probes["debug"].get("status") == 200,
        "robots_disallow": bool(probes["robots"].get("disallow")),
        "tech_stack": PENTEST_HOME_TITLE in str(
            probes["home"].get("title", "")),
    }


# ----------------------------------------------------------------------
# 真实靶场套件（DVWA / Juice Shop / SW-Secure Lab）
#
# 与渗透侦察套件的区别：那个打自造的演示靶（examples/target.py，三个端点）；
# 这个打**业界标准的真实漏洞应用**——攻击面更广、框架特征更真实。
# 预期发现清单定义在 examples/lab.py，探测经内核注册表（同 agent 路径）。
# ----------------------------------------------------------------------
def run_lab_suite(root: Path, driver: str = "scripted") -> list[CaseResult]:
    """真实靶场基线：对运行中的靶场做被动侦察并断言预期发现。

    靶不可达 -> 该靶标记 skipped 并给出启动提示（环境缺失不等于能力不足）。
    **容器生命周期不归本模块管**——绝不 stop / rm 使用者的容器。
    """
    examples = str(ROOT / "examples")
    if examples not in sys.path:
        sys.path.insert(0, examples)
    try:
        from lab import DEFAULT_URLS, LABS, identifies, probe_lab
    except Exception as exc:                              # noqa: BLE001
        return [CaseResult(
            suite="lab", case_id="__env__", category="env", outcome="skipped",
            passed=False, detail=f"lab 模块不可用: {exc}")]

    registry = None
    results: list[CaseResult] = []
    for lab in LABS:
        base = DEFAULT_URLS.get(lab.id, "")
        started = time.time()
        if not base or not identifies(lab, base):
            results.append(CaseResult(
                suite="lab", case_id=lab.id, category="recon",
                outcome="skipped", passed=False,
                elapsed_s=round(time.time() - started, 2),
                expected=f"{len(lab.findings)} 项预期发现",
                detail=f"靶不在：不可达，或端口被别的服务占用（{lab.hint}）"))
            continue
        try:
            if registry is None:
                from lab import _kernel_registry

                registry = _kernel_registry()
            hits = probe_lab(lab, base, registry=registry)
        except Exception as exc:                          # noqa: BLE001
            results.append(CaseResult(
                suite="lab", case_id=lab.id, category="recon",
                outcome="failed", passed=False,
                elapsed_s=round(time.time() - started, 2),
                detail=f"{type(exc).__name__}: {exc}"))
            continue
        matched = sum(1 for v in hits.values() if v)
        total = len(hits)
        passed = bool(total) and matched == total
        missed = [k for k, v in hits.items() if not v]
        results.append(CaseResult(
            suite="lab", case_id=lab.id, category="recon",
            outcome="success" if passed else "failed", passed=passed,
            steps=matched, elapsed_s=round(time.time() - started, 2),
            expected=f"{total} 项预期发现全命中",
            got=f"{matched}/{total}",
            detail="" if passed else f"未命中: {', '.join(missed)}"))
    return results


# ----------------------------------------------------------------------
# 07 靶场套件（进化收益 / 闭环策略对比）
#
# 这两条能力此前只有直跑脚本（eval_evolution / eval_closed_loop），指标不进
# 评分卡、无法跨版本比对。这里**复用它们的既有核心函数**（已实测验证过），
# 只把指标包成统一的 CaseResult——不重写内部逻辑。
# ----------------------------------------------------------------------
def _g07_evolution_case() -> CaseResult:
    """进化收益：技能注入后决策步数应低于探索型（`eval_evolution` 的指标）。"""
    started = time.time()
    cid, category = "evolution-steps-reduced", "evolution"
    try:
        from eval_evolution import (NAIVE_SEQUENCE, SKILL_SEQUENCE,
                                    make_sim_host, register_sim_tools,
                                    run_sequence)

        from penagent.tools import ToolRegistry

        def _avg_steps(sequence) -> Optional[float]:
            steps = []
            for _ in range(5):
                host = make_sim_host()
                reg = ToolRegistry()
                register_sim_tools(reg, host)
                s, ok = run_sequence(reg, host, list(sequence), authorize=True)
                steps.append(s if ok else None)
            won = [s for s in steps if s is not None]
            return sum(won) / len(won) if won else None

        naive = _avg_steps(NAIVE_SEQUENCE)
        evolved = _avg_steps(SKILL_SEQUENCE)
        passed = bool(naive and evolved and evolved < naive)
        return CaseResult(
            suite="g07", case_id=cid, category=category,
            outcome="success" if passed else "failed", passed=passed,
            steps=int(evolved or 0), elapsed_s=round(time.time() - started, 2),
            expected=f"技能型步数 < 探索型（探索型 {naive}）",
            got=f"技能型 {evolved}",
            detail="" if passed else f"技能型 {evolved} 未低于探索型 {naive}")
    except Exception as exc:                              # noqa: BLE001
        return CaseResult(
            suite="g07", case_id=cid, category=category, outcome="failed",
            passed=False, elapsed_s=round(time.time() - started, 2),
            detail=f"{type(exc).__name__}: {exc}")


def _g07_closed_loop_cases() -> list[CaseResult]:
    """闭环策略对比：Q 学习 / PPO 相对基线的步数收益。

    `eval_closed_loop.train_and_evaluate()` 的 PPO 层需 torch（可选依赖，
    不进 requirements）——缺 torch 时本组标记 skipped，而不是判失败。
    """
    try:
        import torch  # noqa: F401
    except ModuleNotFoundError:
        return [CaseResult(
            suite="g07", case_id="closed-loop-policy", category="evolution",
            outcome="skipped", passed=False,
            detail="闭环套件含 PPO 层，需 torch（可选依赖，不入 requirements）")]

    started = time.time()
    try:
        from eval_closed_loop import train_and_evaluate

        rows = {r["name"]: r for r in train_and_evaluate()}
        out = []
        for key, label in (("+Q学习", "qlearning"), ("+PPO", "ppo")):
            r = rows.get(key)
            gain = float(r["gain_vs_baseline"]) if r else 0.0
            passed = bool(r and gain > 0)
            out.append(CaseResult(
                suite="g07", case_id=f"closed-loop-{label}",
                category="evolution",
                outcome="success" if passed else "failed", passed=passed,
                steps=int(r["avg_steps"] or 0) if r else 0,
                elapsed_s=round(time.time() - started, 2),
                expected="相对基线的决策步数收益 > 0",
                got=f"{gain:+.0%}",
                detail="" if passed else f"{key} 相对基线收益 {gain:+.0%}，未为正"))
        return out
    except Exception as exc:                              # noqa: BLE001
        return [CaseResult(
            suite="g07", case_id="closed-loop-policy", category="evolution",
            outcome="failed", passed=False,
            elapsed_s=round(time.time() - started, 2),
            detail=f"{type(exc).__name__}: {exc}")]


def run_g07_suite(root: Path, driver: str = "scripted") -> list[CaseResult]:
    """07 靶场套件：进化收益 + 闭环策略对比。

    07 靶场缺失时整组标记 skipped——环境缺失不等于能力不足（同渗透套件的口径）。
    """
    from penagent.envcfg import ensure_g07_on_path

    if ensure_g07_on_path() is None:
        return [CaseResult(
            suite="g07", case_id="__env__", category="env", outcome="skipped",
            passed=False,
            detail="未找到 07 靶场（把 PENTEST_G07_ROOT 指向 07-agent-war-range 后可用）")]

    examples = str(ROOT / "examples")
    if examples not in sys.path:
        sys.path.insert(0, examples)

    results = [_g07_evolution_case()]
    results.extend(_g07_closed_loop_cases())
    return results


def run_agent_lab_suite(root: Path, driver: str = "agent",
                        max_steps: int = 12,
                        labs: Optional[list[str]] = None,
                        seed: bool = False, reset: bool = False,
                        repeat: int = 1, raw_tag: str = "") -> list[CaseResult]:
    """agent 驱动的真实靶场评测：让 agent 自己决定探什么。

    与上面的 `lab` 套件互补——那个是脚本直探工具链（不经 agent 决策），
    这个把决策交给 agent，判定回到证据链核对预期发现。实现在
    `examples/lab_agent.py`（判分逻辑是纯函数，可单测、可复算）。

    `labs` 只跑指定靶（如 `["dvwa"]`）——单靶迭代时不必付三靶的时间与花费。
    `seed=True` 按靶写入预置技能（`penagent/skill_seeds.py`），用于验证
    技能注入的收益。
    """
    examples = str(ROOT / "examples")
    if examples not in sys.path:
        sys.path.insert(0, examples)
    from lab_agent import run_agent_lab_suite as _run  # noqa: E402

    return _run(root, driver=driver, max_steps=max_steps, labs=labs,
                seed=seed, reset=reset, repeat=repeat, raw_tag=raw_tag)


def _dsh_paths() -> tuple[Path, Path, Path]:
    """宿主桥的三个文件（spool / 证据链 / 增量状态）——独立于内核任务链。"""
    data_dir = ROOT / "data"
    return (data_dir / "dsh-events.jsonl", data_dir / "dsh-chain.jsonl",
            data_dir / "dsh-spool.state.json")


def _record_preset(rec) -> str:
    """证据记录声明的 preset 归属（缺字段 / 为空 = 未知，见 R-22）。"""
    content = getattr(rec, "content", None) or {}
    return str(content.get("preset") or "")


def _owner_retained(owner: str, preset: str) -> bool:
    """**提取**口径：这条会话记录算不算数。

    空 `preset` = 不过滤（全留）；归属未知也留——R-22 的取舍：丢数据是静默的，
    多留是可查的（老链上没有 `preset` 字段）。
    """
    return not preset or not owner or fnmatch.fnmatchcase(owner, preset)


def _owner_attributed(owner: str, preset: str) -> bool:
    """**判分**口径：这条记录能不能证明"本 preset 的会话打过这个靶"。

    与 `_owner_retained` 的分工是刻意的：提取可以宽容（不静默丢数据），判分必须
    严格——归属未知的记录可能来自任何会话（实测：开发会话里读测试文件、跑冒烟
    探测都会留下这种记录），拿它给 Proteus 打分就是 R-41 说的"污染通过率"。
    空 `preset` = 调用方显式要求不过滤，此时一律算归属（`--preset=` 的旧口径）。
    """
    if not preset:
        return True
    return bool(owner) and fnmatch.fnmatchcase(owner, preset)


def dsh_records_for_lab(records, base_url: str, preset: str = "") -> list:
    """挑出"打过某个靶"的证据记录：args 里出现该靶 base URL 的 tool_call。

    `preset` 非空时按 preset 归属过滤（R-22）：`session/event` 是**全局**事件，
    同一个 DSH 进程里所有会话的调用都会进 spool——不过滤的话"这个靶拿了多少分"
    算的是整个进程的动作合集，不是这次 Proteus 任务的。

    `preset` 支持 `modes.py` 同款 fnmatch 家族通配（三个渲染出来的 preset 是
    `proteus-pentest` / `proteus-ctf-web` / `proteus-ctf-crypto`，写 `proteus`
    一条都对不上，要写 `proteus*`）；**是否算归属**由 `_owner_attributed` 判。

    **归属未知（''）不过滤**：字段是 2026-09-22 才加的，老链上没有它；按未知
    保留比按未知丢弃安全（丢数据是静默的，多留是可查的）。

    纯函数（不碰文件、不碰网络），判定口径要能被单测钉住。
    """
    picked = []
    base = (base_url or "").rstrip("/")
    if not base:
        return picked
    for rec in records:
        if getattr(rec, "kind", "") != "tool_call":
            continue
        owner = _record_preset(rec)
        if not _owner_retained(owner, preset):
            continue
        blob = json.dumps((getattr(rec, "content", None) or {}).get("args", ""),
                          ensure_ascii=False)
        if base in blob:
            picked.append(rec)
    return picked


def dsh_lab_verdict(lab, picked: list, hits: dict, chain_ok: bool,
                    attributed: Optional[int] = None,
                    preset: str = "proteus*") -> tuple[str, str]:
    """判定一个靶在宿主会话里的评测口径：返回 `(outcome, detail)`。

    为什么不能一律 FAIL：`dsh-session` 是**回放**套件——它自己不发起任何调用，
    只在历史会话记录里判分，于是旧口径下"会话根本没做过这个靶"与"做了但全失败"
    是同一个 FAIL。前者不是能力不足，而是**没有测量**（同 `pentest` / `lab`
    套件"靶不可达"的 skip 语义），记 FAIL 会拿无关会话污染总通过率与退出码
    （见 `docs/修复待办清单.md` R-41，实测三例：两个靶一项都没命中、一个只被
    冒烟式碰过两下）。

    判分要求两条同时成立（对应台账里的"无匹配会话"与"证据不足"两半）：

    1. **有匹配会话**：该靶至少有一条记录**明确归属该 preset**。归属未知的记录
       （老链没有 `preset` 字段 / 会话本来就没跑 Proteus preset）仍被提取出来计数
       （R-22：不静默丢数据），但它证明不了"这次 Proteus 任务打过这个靶"——
       传空的 `--preset`（显式要求不过滤）时才按全集判分；
    2. **证据充分**：命中**入口（`home`）之外**至少一项预期发现——说明这次会话确实
       在推进该靶的侦察面；只触达首页属冒烟级，与"没做过"无法区分。

    外加链校验通过（硬门槛，与 `agent-lab` 同口径）。

    `attributed`：picked 里明确归属该 preset 的记录数（缺省 None = 与 picked 等长，
    即调用方已自行保证归属）。返回 `skipped` 时 detail 写明是哪一种"没测量"
    （无归属记录 / 无侦察证据 / 仅触达入口），事后能把"没人打这个靶"与
    "打了没得分"分开。

    纯函数（不碰文件、不碰网络），判定口径能被单测钉住。
    """
    from lab import identity_finding

    entry = identity_finding(lab)
    entry_name = entry.name if entry is not None else ""
    owned = len(picked) if attributed is None else attributed
    matched = sum(1 for v in hits.values() if v)
    total = len(hits)
    beyond_entry = matched - (1 if entry_name and hits.get(entry_name) else 0)
    scope = ("preset=" + preset) if preset else "全部 preset"

    if not picked:
        return "skipped", (f"无可归属该靶的会话记录（{scope} 的会话累计未打过 "
                           f"{lab.id}）")
    if not owned:
        return "skipped", (f"会话记录均未明确归属 {scope}（老链没有归属字段，或那次"
                           f"会话本来就没跑 Proteus preset）——不作能力判分；"
                           f"要看不过滤口径请传空的 --preset")
    if not chain_ok:
        return "failed", "证据链校验未通过（命中一概不作数）"
    if matched == 0:
        return "skipped", (f"会话记录未命中该靶任何预期发现（调用 {len(picked)} 次）"
                           f"——无侦察证据，可能是别的任务顺带碰过该地址")
    if beyond_entry <= 0:
        return "skipped", (f"仅触达入口（{entry_name or 'home'}）共 {matched}/{total} 项，"
                           f"属冒烟级调用，不构成该靶的侦察评测")
    if matched < total:
        missed = ', '.join(k for k, v in hits.items() if not v)
        return "failed", f"未探到: {missed}"
    return "success", ""


def run_dsh_session_suite(root: Path, driver: str = "scripted",
                          preset: str = "proteus*") -> list[CaseResult]:
    """DSH 宿主会话套件：读宿主桥证据链，按靶场清单判定（不需要 LLM、靶场可离线）。

    与 `agent-lab` 的分工：那个跑内核自己的 ReAct 循环；这个判定的是**宿主会话**
    （DSH web / headless）里真实发生过的工具调用。两条路径共用同一套 ground truth
    与同一个判定函数（`score_from_evidence`），靠 `python -m penagent dsh-sync`
    把 spool 落进独立链——"旁路也留痕、痕迹能评分"就落在这一步。

    链校验是硬门槛：链不过，命中一概不作数（与 agent-lab 同口径）。

    **逐靶用例是"有则判分、无则跳过"**：历史会话没做过某个靶、或该靶的记录都
    不属于本 preset（老链无归属字段 / 会话没跑 Proteus preset）时记 `skipped`
    而不是 FAIL（判据见 `dsh_lab_verdict`）——回放套件量不到的东西不算能力不足。

    `preset`：只算属于该 preset 的会话记录（缺省 `proteus`；传空串 = 不过滤，
    兼容 2026-09-22 之前没有归属字段的老链）。注意"提取"与"判分"是两层门槛：
    归属未知的记录仍被提取计数（R-22：不静默丢数据），但要判分得先有明确归属。
    """
    examples = str(ROOT / "examples")
    if examples not in sys.path:
        sys.path.insert(0, examples)
    from lab import DEFAULT_URLS, LABS                    # noqa: E402
    from lab_agent import score_from_evidence             # noqa: E402
    from penagent.dsh_bridge import import_spool          # noqa: E402
    from penagent.evidence import EvidenceChain           # noqa: E402

    spool, chain_path, state_path = _dsh_paths()
    if not spool.exists() and not chain_path.exists():
        return [CaseResult(
            suite="dsh-session", case_id="__env__", category="env",
            outcome="skipped", passed=False,
            detail="宿主桥尚未产出（先跑一次 DSH 会话，再 "
                   "python -m penagent dsh-sync）")]
    try:
        import_spool(spool=spool, chain_path=chain_path, state_path=state_path)
    except Exception as exc:                              # noqa: BLE001
        return [CaseResult(
            suite="dsh-session", case_id="__env__", category="env",
            outcome="failed", passed=False,
            detail=f"导入 spool 失败: {type(exc).__name__}: {exc}")]

    chain = EvidenceChain(chain_path)
    records = chain.load()
    verify = chain.verify()
    chain_ok = bool(verify.get("ok"))
    results = [CaseResult(
        suite="dsh-session", case_id="chain-integrity", category="audit",
        outcome="success" if chain_ok else "failed", passed=chain_ok,
        steps=int(verify.get("length") or 0),
        expected="宿主桥证据链校验通过（链式哈希）",
        got=f"长度 {verify.get('length')}",
        detail="" if chain_ok else
               f"tampered={verify.get('tampered')} "
               f"broken={verify.get('broken_links')}")]

    # P2-2：守卫可观测一行（观测行，不参与通过率）——裁决分布 / 同指纹重复率 /
    # 步数分布 / 假声明率。守卫参数此前只能凭感觉调，这一行把它们的影响摊开。
    try:
        from penagent.guard_stats import collect, render

        stats = collect(chain_path.parent, spool_path=spool, preset=preset)
        results.append(CaseResult(
            suite="dsh-session", case_id="guard-stats", category="audit",
            outcome="success", passed=True,
            steps=int(stats.get("records") or 0),
            expected="守卫与声明统计可读（裁决/重复率/步数/假声明率）",
            got="; ".join(render(stats).splitlines()[1:]),
            detail=render(stats)))
    except Exception as exc:                              # noqa: BLE001
        results.append(CaseResult(
            suite="dsh-session", case_id="guard-stats", category="audit",
            outcome="skipped", passed=False,
            detail=f"统计不可读（不影响其它用例）: {type(exc).__name__}: {exc}"))

    for lab in LABS:
        base = DEFAULT_URLS.get(lab.id, "")
        picked = dsh_records_for_lab(records, base, preset=preset)
        hits = score_from_evidence(lab.findings, picked)
        matched = sum(1 for v in hits.values() if v)
        total = len(hits)
        # 明确归属该 preset 的记录数（preset="" 即调用方要求不过滤，视作全归属）
        attributed = sum(1 for r in picked
                         if _owner_attributed(_record_preset(r), preset))
        outcome, detail = dsh_lab_verdict(lab, picked, hits, chain_ok,
                                          attributed=attributed, preset=preset)
        owner_note = (f"，其中明确归属 {preset} 的 {attributed} 次"
                      if preset and attributed != len(picked) else "")
        results.append(CaseResult(
            suite="dsh-session", case_id=lab.id, category="recon-dsh",
            outcome=outcome, passed=outcome == "success",
            steps=attributed,
            expected=f"{total} 项预期发现（宿主会话内真实调用）",
            got=f"{matched}/{total} 命中 · 调用 {len(picked)} 次"
                f"（{('preset=' + preset) if preset else '全部 preset'} 的会话累计"
                f"{owner_note}）",
            detail=detail))
    return results


SUITES: dict[str, Callable[..., list[CaseResult]]] = {
    "ctf": run_ctf_suite,
    "pentest": run_pentest_suite,
    "lab": run_lab_suite,
    "agent-lab": run_agent_lab_suite,
    "dsh-session": run_dsh_session_suite,
    "g07": run_g07_suite,
}

# `--suite all` 不含 agent-lab：它按靶调用真实 LLM（有实际花费与分钟级时长），
# 应当由使用方显式点名运行，而不是被"跑一遍看总分"顺带触发。
ALL_SUITES_EXCLUDE = {"agent-lab"}


# ----------------------------------------------------------------------
# 编排
# ----------------------------------------------------------------------
def run(suites: list[str], driver: str = "scripted",
        workdir: Optional[Path] = None,
        pentest_target: str = "127.0.0.1",
        pentest_port: int = 8090,
        agent_max_steps: int = 12,
        agent_labs: Optional[list[str]] = None,
        agent_seed: bool = False,
        agent_reset: bool = False,
        agent_repeat: int = 1,
        agent_raw_tag: str = "",
        dsh_preset: str = "proteus*") -> Scorecard:
    """跑指定套件，汇总为一张评分卡。

    渗透套件的靶地址可传（`--target` / `--port`），否则本机 8080 被别的服务
    占用时既没法指定靶、也没法触发 skipped 路径。
    """
    card = Scorecard(driver=driver,
                     started_at=time.strftime("%Y-%m-%d %H:%M:%S"))
    base = Path(workdir) if workdir else DEFAULT_OUT
    for name in suites:
        runner = SUITES.get(name)
        if runner is None:
            card.results.append(CaseResult(
                suite=name, case_id="__suite__", outcome="skipped",
                passed=False, detail=f"未知套件 {name}（可用 {sorted(SUITES)}）"))
            continue
        if name == "pentest":
            card.results.extend(runner(base / name, driver=driver,
                                       target=pentest_target,
                                       port=pentest_port))
        elif name == "agent-lab":
            card.results.extend(runner(base / name, driver=driver,
                                       max_steps=agent_max_steps,
                                       labs=agent_labs, seed=agent_seed,
                                       reset=agent_reset,
                                       repeat=agent_repeat,
                                       raw_tag=agent_raw_tag))
        elif name == "dsh-session":
            card.results.extend(runner(base / name, driver=driver,
                                       preset=dsh_preset))
        else:
            card.results.extend(runner(base / name, driver=driver))
    return card


def save(card: Scorecard, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(card.to_dict(), ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return path


def load(path: Path) -> Scorecard:
    return Scorecard.from_dict(
        json.loads(Path(path).read_text(encoding="utf-8")))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python examples/benchmark.py",
        description="统一评测骨架：跑一批用例，产出可对比的评分卡")
    parser.add_argument("--suite", default="ctf",
                        help="套件：ctf / pentest / lab / agent-lab / g07 / all"
                             "（逗号分隔，默认 ctf；all 不含 agent-lab）")
    parser.add_argument("--driver", default="",
                        choices=("", "scripted", "llm", "agent"),
                        help="决策驱动（缺省按套件推断：agent-lab 记 agent，"
                             "其余记 scripted；scripted 离线确定性 / "
                             "llm 真实模型 / agent 由 agent 自主决策）")
    parser.add_argument("--out", default="",
                        help=f"结果落盘路径（缺省 {DEFAULT_OUT}/run.json）")
    parser.add_argument("--compare", default="",
                        help="与基线结果 JSON 对比（逐例给出改进/回归）")
    parser.add_argument("--target", default="127.0.0.1",
                        help="渗透套件的靶主机（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=8090,
                        help="渗透套件的靶端口（默认 8090；8080 常被真实靶场占用）")
    parser.add_argument("--max-steps", type=int, default=12,
                        help="agent-lab 套件的单靶决策步数上限（默认 12）")
    parser.add_argument("--labs", default="",
                        help="agent-lab 只跑指定靶（逗号分隔，如 dvwa；缺省全跑）")
    parser.add_argument("--seed-skills", action="store_true",
                        help="agent-lab 按靶注入预置技能（penagent/skill_seeds.py）"
                             "，用于验证技能收益")
    parser.add_argument("--reset-memory", action="store_true",
                        help="agent-lab 跑前清空该靶的评测沙箱记忆"
                             "（只动 data/benchmark/agent-lab/<靶>/mem，"
                             "不碰生产记忆库）；测对照组时需要")
    parser.add_argument("--preset", default="proteus*",
                        help="dsh-session 套件只算该 preset 的会话记录，支持 "
                             "fnmatch 家族通配（默认 proteus* = 三个 Proteus "
                             "preset；空串 = 不过滤，兼容老链）")
    parser.add_argument("--repeat", type=int, default=1,
                        help="agent-lab 每靶重复轮数（温度 0.3 下用来看稳定性；"
                             "每轮一条用例，case_id 带 #序号）")
    args = parser.parse_args(argv)

    suites = (sorted(set(SUITES) - ALL_SUITES_EXCLUDE)
              if args.suite == "all"
              else [s.strip() for s in args.suite.split(",") if s.strip()])
    labs = [s.strip() for s in args.labs.split(",") if s.strip()] or None
    # 驱动标签：agent-lab 本质是 agent 驱动，不传 --driver 时不该记成 scripted
    # （标错会让"这张卡是怎么来的"无从判断）
    driver = args.driver or ("agent" if "agent-lab" in suites else "scripted")
    card = run(suites, driver=driver, pentest_target=args.target,
               pentest_port=args.port, agent_max_steps=args.max_steps,
               agent_labs=labs, agent_seed=args.seed_skills,
               agent_reset=args.reset_memory, agent_repeat=args.repeat,
               agent_raw_tag=Path(args.out).stem if args.out else "",
               dsh_preset=args.preset)
    print(card.render())

    out = Path(args.out) if args.out else DEFAULT_OUT / "run.json"
    print(f"结果已落盘: {save(card, out)}")

    if args.compare:
        baseline = load(args.compare)
        diff = card.compare(baseline)
        print("\n与基线对比:")
        print(f"  通过率 {diff['pass_rate']['before']:.0%} -> "
              f"{diff['pass_rate']['after']:.0%} "
              f"({diff['pass_rate']['delta']:+.0%})")
        print(f"  平均步数 {diff['avg_steps']['before']} -> "
              f"{diff['avg_steps']['after']} "
              f"({diff['avg_steps']['delta']:+.2f})")
        if diff["fixed"]:
            print(f"  修复: {', '.join(diff['fixed'])}")
        if diff["regressed"]:
            print(f"  回归: {', '.join(diff['regressed'])}")
    return 0 if not card.failures() else 1


if __name__ == "__main__":
    raise SystemExit(main())
