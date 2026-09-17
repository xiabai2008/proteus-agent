"""Proteus Web 控制台后端：直连 penagent（CLI 子进程 / SDK），不经过 DSH 宿主。

三个视图对应的接口：
- 模式选择与关键词触发  GET  /api/modes 、POST /api/suggest
- 任务下发与实时步骤流  POST /api/tasks 、GET /api/stream/<mission>
- 证据链校验视图        GET  /api/missions/<mode> 、GET /api/evidence/<mode>/<mission>

任务执行有两种驱动：
- ``penagent``：真实内核 CLI 子进程（``python -m penagent run --mode ...``），
  需要配置 PENTEST_LLM_* 才能跑 LLM 决策循环。
- ``scripted``：离线脚本化决策（仓库无 API key 时的演示驱动）。它同样走内核
  的真实路径——真工具、真证据链、真判定器——只有"模型选哪个工具"这一步由脚本
  扮演，因此步骤流与 flag 判定与真实运行同源。

仅用标准库，零新增依赖（AGENTS.md 硬规则 5）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from penagent.evidence import EvidenceChain  # noqa: E402
from penagent.memory import Memory  # noqa: E402
from penagent.modes import ModeProfile, load_modes  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
DEFAULT_DATA = REPO_ROOT / "data"


# ----------------------------------------------------------------------
# 服务层（纯逻辑，可单测；HTTP 层只是薄适配）
# ----------------------------------------------------------------------
class ConsoleService:
    """控制台服务：模式、任务、步骤流、证据链。"""

    def __init__(self, data_dir: Path = DEFAULT_DATA,
                 repo_root: Path = REPO_ROOT) -> None:
        self.data_dir = Path(data_dir)
        self.repo_root = Path(repo_root)
        self._lock = threading.Lock()
        self._missions: dict[str, dict] = {}     # mission_id -> 运行态
        self._modes: dict[str, ModeProfile] = load_modes(
            self.repo_root / "modes")

    # ---------------- 模式 ----------------
    def modes(self) -> list[dict]:
        out = []
        for mode in self._modes.values():
            if mode.id == "base":
                continue          # base 是继承用的公共默认，不作为运行模式
            verifier = mode.verifier
            out.append({
                "id": mode.id,
                "label": mode.label,
                "triggers": list(mode.triggers),
                "sandbox": mode.sandbox,
                "memory_namespace": mode.memory_namespace,
                "skills": list(mode.skills),
                "capability": {
                    "allow": list(mode.capability.allow),
                    "deny": list(mode.capability.deny),
                    "constraints": dict(mode.capability.constraints),
                },
                "permission": {
                    "default": mode.permission.default,
                    "auto_approve": list(mode.permission.auto_approve),
                    "require_confirm": list(mode.permission.require_confirm),
                    "hard_deny": list(mode.permission.hard_deny),
                },
                "budget": {
                    "max_steps": mode.budget.max_steps,
                    "max_minutes": mode.budget.max_minutes,
                    "max_cost_usd": mode.budget.max_cost_usd,
                },
                "verifier": {
                    "type": verifier.type,
                    "pattern": verifier.pattern,
                    "auto_retry": verifier.auto_retry,
                    "require_poc": verifier.require_poc,
                },
            })
        return out

    def suggest(self, text: str) -> list[dict]:
        """按关键词触发推荐模式（命中数降序）。"""
        scored = []
        for mode_id, mode in self._modes.items():
            if mode_id == "base":
                continue
            hits = mode.matches_keywords(text)
            if hits:
                scored.append({"id": mode_id, "label": mode.label,
                               "hits": hits, "score": len(hits)})
        return sorted(scored, key=lambda item: -item["score"])

    def mode(self, mode_id: str) -> ModeProfile:
        if mode_id not in self._modes:
            raise KeyError(f"未知模式: {mode_id}")
        return self._modes[mode_id]

    # ---------------- 任务 ----------------
    def dispatch(self, mode_id: str, target: str, objective: str,
                 *, driver: str = "scripted", challenge: str = "",
                 authorize: bool = True) -> dict:
        """下发任务：起一个后台线程跑内核（两种驱动都在线程里）。"""
        mode = self.mode(mode_id)
        mission_key = f"{mode_id}-{int(time.time() * 1000)}"
        state = {"key": mission_key, "mode": mode_id, "driver": driver,
                 "mission_id": "", "status": "running", "error": "",
                 "challenge": challenge, "started_at": time.time()}
        with self._lock:
            self._missions[mission_key] = state

        def _run() -> None:
            try:
                mission_id = self._run_mission(mode, target, objective,
                                               driver=driver,
                                               challenge=challenge,
                                               authorize=authorize)
                state["mission_id"] = mission_id
            except Exception as exc:                      # noqa: BLE001
                state["status"] = "error"
                state["error"] = str(exc)
                return
            state["status"] = "finished"

        threading.Thread(target=_run, name=f"mission-{mission_key}",
                         daemon=True).start()
        return state

    def _run_mission(self, mode: ModeProfile, target: str, objective: str,
                     *, driver: str, challenge: str, authorize: bool) -> str:
        if driver == "penagent":
            return self._run_cli(mode, target, objective, authorize)
        if driver == "scripted":
            return self._run_scripted(mode, target, objective, challenge)
        raise ValueError(f"未知驱动: {driver}")

    def _run_cli(self, mode: ModeProfile, target: str, objective: str,
                 authorize: bool) -> str:
        """真实驱动：CLI 子进程（步骤由内核写进 memory，流从 memory 读）。"""
        import subprocess

        cmd = [sys.executable, "-m", "penagent", "run",
               "--mode", mode.id, "--target", target,
               "--objective", objective,
               "--data", str(self.data_dir),
               "--targets", "127.0.0.1"]
        if authorize:
            cmd.append("--authorize")
        proc = subprocess.run(cmd, cwd=str(self.repo_root), capture_output=True,
                              text=True, encoding="utf-8", errors="replace")
        if proc.returncode != 0:
            raise RuntimeError(f"内核退出码 {proc.returncode}: "
                               f"{(proc.stderr or proc.stdout)[-300:]}")
        match = re.search(r"作战记录: (\S+)", proc.stdout or "")
        if not match:
            raise RuntimeError("未能从内核输出里解析 mission id")
        return Path(match.group(1)).stem

    def _run_scripted(self, mode: ModeProfile, target: str, objective: str,
                      challenge: str) -> str:
        """离线驱动：脚本化决策 + 真实内核路径（工具/证据链/判定器都是真的）。"""
        import penagent.agent as agent_mod
        from penagent.agent import PenAgent, Policy
        from penagent.llm import LLMConfig
        from penagent.registry import build_center

        examples = self.repo_root / "examples"
        if str(examples) not in sys.path:
            sys.path.insert(0, str(examples))
        from eval_ctf_solve import _solve_script, build_challenges  # noqa: E402

        demo_root = self.data_dir / "ctf-demo"
        challenges = build_challenges(demo_root)
        if challenge:
            if challenge not in challenges:
                raise ValueError(f"未知样例题: {challenge}")
            picked = {challenge: challenges[challenge]}
        else:
            picked = challenges

        memory = Memory(self.data_dir, namespace=mode.memory_namespace)
        # 与 CLI 驱动共用同一条证据链，证据视图才有单一来源
        evidence = EvidenceChain(self.data_dir / "chain.jsonl")
        registry = build_center().build_registry(mode)
        agent = PenAgent(registry, memory, evidence, LLMConfig(),
                         Policy(allowed_targets=["127.0.0.1"],
                                authorize=True),
                         mode=mode)

        original = agent_mod.chat_json
        mission_id = ""
        try:
            for cid, meta in picked.items():
                decisions = _solve_script(cid, meta)
                agent_mod.chat_json = lambda c, m, **kw: decisions.pop(0)
                result = agent.run(str(meta["file"]),
                                  f"{objective}（样例题 {cid}）")
                mission_id = result.mission_id
        finally:
            agent_mod.chat_json = original
        return mission_id

    def mission_state(self, key: str) -> dict:
        with self._lock:
            state = self._missions.get(key)
        if state is None:
            raise KeyError(f"未知任务: {key}")
        return dict(state)

    # ---------------- 作战记录与步骤流 ----------------
    def missions(self, mode_id: str) -> list[dict]:
        mode = self.mode(mode_id)
        memory = Memory(self.data_dir, namespace=mode.memory_namespace)
        records = memory.list_missions()
        records.sort(key=lambda r: r.get("started_at", ""), reverse=True)
        return [{"id": r.get("id"), "target": r.get("target"),
                 "objective": r.get("objective"),
                 "outcome": r.get("outcome"),
                 "started_at": r.get("started_at"),
                 "finished_at": r.get("finished_at"),
                 "steps": len(r.get("steps") or [])} for r in records]

    def mission(self, mode_id: str, mission_id: str) -> dict:
        mode = self.mode(mode_id)
        memory = Memory(self.data_dir, namespace=mode.memory_namespace)
        return memory.get_mission(mission_id)

    def flag_hit(self, mode_id: str, text: str) -> str:
        """按模式的 verifier 正则从文本里取 flag（判定器同源）。"""
        mode = self.mode(mode_id)
        pattern = mode.verifier.pattern
        if mode.verifier.type != "flag_regex" or not pattern:
            return ""
        match = re.search(pattern, text or "")
        return match.group(0) if match else ""

    def stream_events(self, mode_id: str, mission_id: str,
                      *, poll: float = 0.4,
                      timeout: float = 180.0):
        """增量产出步骤事件（SSE 用），任务收口后给出判定事件并结束。"""
        mode = self.mode(mode_id)
        memory = Memory(self.data_dir, namespace=mode.memory_namespace)
        seen = 0
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                record = memory.get_mission(mission_id)
            except (FileNotFoundError, json.JSONDecodeError):
                yield {"type": "waiting", "mission_id": mission_id}
                time.sleep(poll)
                continue
            steps = record.get("steps") or []
            while seen < len(steps):
                yield {"type": "step", "index": seen + 1, "step": steps[seen]}
                seen += 1
            if record.get("outcome") not in ("", "running", None):
                summary = record.get("reflection") or \
                    self._last_conclusion_summary()
                # flag 语料与判定器同源：收口结论 + 本任务期间的工具输出
                corpus = "\n".join(
                    [summary] + [str(s.get("output", "")) for s in steps])
                yield {"type": "verdict",
                       "outcome": record.get("outcome"),
                       "summary": summary,
                       "flag": self.flag_hit(mode_id, corpus),
                       "steps": len(steps)}
                return
            time.sleep(poll)
        yield {"type": "timeout", "mission_id": mission_id}

    def _last_conclusion_summary(self) -> str:
        """取证据链里最近一条收口结论（成功路径的总结不落在作战记录里）。"""
        try:
            records = EvidenceChain(self.data_dir / "chain.jsonl").load()
        except Exception:                                  # noqa: BLE001
            return ""
        for record in reversed(records):
            if record.kind == "conclusion":
                content = record.content or {}
                return f"{content.get('summary', '')}｜{content.get('verdict', '')}"
        return ""

    # ---------------- 证据链 ----------------
    def evidence_view(self, mode_id: str, mission_id: str = "") -> dict:
        mode = self.mode(mode_id)
        chain_files = sorted(self.data_dir.glob("*.jsonl"))
        chain = EvidenceChain(self.data_dir / "chain.jsonl")
        records = [r.to_dict() for r in chain.load()]
        view = {
            "chain_file": str(chain.path),
            "chain_files": [p.name for p in chain_files],
            "integrity": chain.verify(),
            "records": records[-80:],
            "total": len(records),
        }
        if mission_id:
            mission = self.mission(mode_id, mission_id)
            refs = [s for s in (mission.get("steps") or [])
                    if s.get("blocked")]
            view["mission"] = {
                "id": mission_id,
                "outcome": mission.get("outcome"),
                "blocked_steps": refs,
            }
            conclusion = [r for r in records if r.get("kind") == "conclusion"]
            view["conclusion"] = conclusion[-1] if conclusion else None
        return view


# ----------------------------------------------------------------------
# HTTP 层
# ----------------------------------------------------------------------
class ConsoleHandler(BaseHTTPRequestHandler):
    """薄适配：路由 + JSON + SSE + 静态文件。"""

    service: ConsoleService = None            # 由 main() 注入
    server_version = "ProteusConsole/0.1"

    def log_message(self, fmt, *args):        # 静音默认访问日志
        return

    # ---------------- 工具 ----------------
    def _json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message}, status=status)

    def _static(self, path: str) -> bool:
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        target = (STATIC_DIR / rel).resolve()
        if STATIC_DIR.resolve() not in target.parents and target != STATIC_DIR:
            self._error(403, "越界路径")
            return True
        if not target.is_file():
            return False
        content_type = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
        }.get(target.suffix, "application/octet-stream")
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return True

    # ---------------- 路由 ----------------
    def do_GET(self) -> None:                 # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        route = parsed.path
        try:
            if route == "/api/modes":
                return self._json({"modes": self.service.modes()})
            if route.startswith("/api/missions/"):
                mode_id = route.rsplit("/", 1)[-1]
                return self._json({"missions": self.service.missions(mode_id)})
            if route.startswith("/api/mission/"):
                _, _, mode_id, mission_id = route.split("/", 3)
                return self._json(self.service.mission(mode_id, mission_id))
            if route.startswith("/api/evidence/"):
                parts = route.split("/")
                mode_id = parts[3] if len(parts) > 3 else ""
                mission_id = parts[4] if len(parts) > 4 else ""
                return self._json(self.service.evidence_view(mode_id,
                                                             mission_id))
            if route.startswith("/api/state/"):
                return self._json(self.service.mission_state(
                    route.rsplit("/", 1)[-1]))
            if route.startswith("/api/stream/"):
                mode_id = query.get("mode", [""])[0]
                mission_id = route.rsplit("/", 1)[-1]
                return self._stream(mode_id, mission_id)
            if self._static(route):
                return
            self._error(404, f"未知路径: {route}")
        except KeyError as exc:
            self._error(404, str(exc))
        except Exception as exc:                          # noqa: BLE001
            self._error(500, f"{type(exc).__name__}: {exc}")

    def do_POST(self) -> None:                # noqa: N802
        route = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            return self._error(400, f"非法 JSON: {exc}")
        try:
            if route == "/api/suggest":
                return self._json({"suggestions":
                                   self.service.suggest(payload.get("text", ""))})
            if route == "/api/tasks":
                state = self.service.dispatch(
                    payload.get("mode", ""), payload.get("target", ""),
                    payload.get("objective", ""),
                    driver=payload.get("driver", "scripted"),
                    challenge=payload.get("challenge", ""),
                    authorize=bool(payload.get("authorize", True)))
                return self._json(state, status=202)
            self._error(404, f"未知路径: {route}")
        except KeyError as exc:
            self._error(404, str(exc))
        except ValueError as exc:
            self._error(400, str(exc))
        except Exception as exc:                          # noqa: BLE001
            self._error(500, f"{type(exc).__name__}: {exc}")

    def _stream(self, mode_id: str, mission_id: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        for event in self.service.stream_events(mode_id, mission_id):
            chunk = f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            try:
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
            if event.get("type") in ("verdict", "timeout"):
                return


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Proteus Web 控制台")
    parser.add_argument("--port", type=int, default=8770)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--data", default=str(DEFAULT_DATA))
    args = parser.parse_args(argv)

    ConsoleHandler.service = ConsoleService(Path(args.data))
    httpd = ThreadingHTTPServer((args.host, args.port), ConsoleHandler)
    print(f"Proteus 控制台: http://{args.host}:{args.port}/  "
          f"(data={args.data})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
