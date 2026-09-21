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
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

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
    from eval_ctf_solve import build_challenges, solve  # noqa: E402

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
            result, _agent = solve(root, cid, meta, mode_id="ctf-crypto")
            elapsed = time.time() - started
            got = meta["flag"] if meta["flag"] in str(result.summary) else ""
            results.append(CaseResult(
                suite="ctf", case_id=cid, category=category,
                outcome=result.outcome,
                passed=(result.outcome == "success"),
                steps=result.steps, elapsed_s=round(elapsed, 2),
                expected=meta["flag"], got=got or str(result.summary)[:80],
                detail="" if result.outcome == "success" else result.summary[:80],
            ))
        except Exception as exc:                          # noqa: BLE001
            results.append(CaseResult(
                suite="ctf", case_id=cid, category=category,
                outcome="failed", passed=False,
                elapsed_s=round(time.time() - started, 2),
                expected=meta["flag"], detail=f"{type(exc).__name__}: {exc}"))
    return results


# 渗透侦察套件的预期发现（本地授权靶 examples/target.py 的已知端点）
PENTEST_EXPECT = {
    "admin_protected": ["/admin", "401"],
    "debug_leak": ["/debug"],
    "robots_disallow": ["disallow"],
    "tech_stack": ["server", "title"],
}


def run_pentest_suite(root: Path, driver: str = "scripted",
                      target: str = "127.0.0.1",
                      port: int = 8080) -> list[CaseResult]:
    """渗透侦察套件：对本地授权靶跑一次侦察，检查是否命中预期发现。

    靶子不可达时**标记 skipped 而不是 failed**——环境缺失不等于能力不足，
    这条区分很重要（否则"没起靶"会被误读成"agent 不行"）。
    """
    started = time.time()
    reachable = _port_open(target, port)
    if not reachable:
        return [CaseResult(
            suite="pentest", case_id="local-portal-recon", category="recon",
            outcome="skipped", passed=False,
            detail=f"靶子 {target}:{port} 不可达（先跑 "
                   f"python examples/target.py --port {port}）")]

    found = _probe_target(target, port)
    matched = [name for name, pats in PENTEST_EXPECT.items()
               if any(p.lower() in found.lower() for p in pats)]
    passed = len(matched) >= 2          # 至少命中两类发现才算侦察有效
    return [CaseResult(
        suite="pentest", case_id="local-portal-recon", category="recon",
        outcome="success" if passed else "failed", passed=passed,
        steps=len(matched), elapsed_s=round(time.time() - started, 2),
        expected="至少 2 类发现（admin/debug/robots/tech）",
        got=",".join(matched) or "无",
        detail="" if passed else f"仅命中 {len(matched)} 类，低于阈值 2",
    )]


def _port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


def _probe_target(host: str, port: int) -> str:
    """对靶做被动侦察，把响应拼成一段文本供预期模式匹配。

    只用内核内置工具（零外部依赖），不引入攻击动作。
    """
    from penagent.builtin_tools import http_probe, robots_fetch

    base = f"http://{host}:{port}"
    chunks = []
    for url in (base, f"{base}/admin", f"{base}/debug"):
        try:
            chunks.append(json.dumps(http_probe(url), ensure_ascii=False))
        except Exception as exc:                          # noqa: BLE001
            chunks.append(f"{url} 探测失败: {exc}")
    try:
        chunks.append(json.dumps(robots_fetch(base), ensure_ascii=False))
    except Exception as exc:                              # noqa: BLE001
        chunks.append(f"robots 失败: {exc}")
    return "\n".join(chunks)


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


SUITES: dict[str, Callable[..., list[CaseResult]]] = {
    "ctf": run_ctf_suite,
    "pentest": run_pentest_suite,
    "g07": run_g07_suite,
}


# ----------------------------------------------------------------------
# 编排
# ----------------------------------------------------------------------
def run(suites: list[str], driver: str = "scripted",
        workdir: Optional[Path] = None,
        pentest_target: str = "127.0.0.1",
        pentest_port: int = 8080) -> Scorecard:
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
                        help="套件：ctf / pentest / all（逗号分隔，默认 ctf）")
    parser.add_argument("--driver", default="scripted",
                        choices=("scripted", "llm"),
                        help="决策驱动（scripted 离线确定性 / llm 真实模型）")
    parser.add_argument("--out", default="",
                        help=f"结果落盘路径（缺省 {DEFAULT_OUT}/run.json）")
    parser.add_argument("--compare", default="",
                        help="与基线结果 JSON 对比（逐例给出改进/回归）")
    parser.add_argument("--target", default="127.0.0.1",
                        help="渗透套件的靶主机（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=8080,
                        help="渗透套件的靶端口（默认 8080）")
    args = parser.parse_args(argv)

    suites = (sorted(SUITES) if args.suite == "all"
              else [s.strip() for s in args.suite.split(",") if s.strip()])
    card = run(suites, driver=args.driver, pentest_target=args.target,
               pentest_port=args.port)
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
