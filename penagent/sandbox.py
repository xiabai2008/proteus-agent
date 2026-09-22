"""沙箱分级执行：模式声明隔离级别，工具声明最低隔离需求。

三档（AGENTS.md 第 4 节 sandbox 字段的实装）：

======== ========================== ==========================================
档位      被动工具                    需要隔离的工具（dangerous / 声明 sandbox）
======== ========================== ==========================================
none     直接执行                    拒绝（none 档只放行白名单内被动工具）
local    直接执行                    直接执行（仍需 Policy 白名单与授权档位）
docker   直接执行                    容器内执行；容器不可用则**拒绝**，绝不裸跑
======== ========================== ==========================================

关键约束（硬规则 1/3）：判定发生在**工具执行前**，且由 ToolRegistry 持有策略
对象来保证——不是靠调用方自觉。容器不可用时拒绝执行而不是降级直跑，是这一档
存在的全部意义。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Optional

LEVELS = ("none", "local", "docker")
DEFAULT_IMAGE = "python:3.12-slim"
# 容器内的工作目录（固定 Linux 路径）：宿主路径不能直接作 -w，见 DockerRunner.wrap
CONTAINER_WORKDIR = "/work"


def tool_needs_isolation(spec) -> bool:
    """工具是否需要隔离执行：显式声明 sandbox，或标记为高危。"""
    declared = str(getattr(spec, "sandbox", "") or "").strip().lower()
    if declared in ("docker", "container"):
        return True
    return bool(getattr(spec, "dangerous", False))


@dataclass(frozen=True)
class SandboxDecision:
    """一次执行前的沙箱裁决结果。"""

    allowed: bool
    reason: str = ""
    isolated: bool = False                       # 是否进容器
    wrap: Optional[Callable[[list], list]] = None  # 命令包装器（容器执行用）


def _basename_no_exe(text: str) -> str:
    """从宿主可执行文件路径取容器内可解析的工具名。

    只对 `.exe` 路径生效（Windows 宿主的工具二进制），且要求确实带目录
    （`base != text`）——否则裸名字（如 `sqlmap`）本身就该原样保留。
    """
    base = os.path.basename(text)
    if base == text or not base.lower().endswith(".exe"):
        return ""
    return base[:-4]


def containerize_command(command: list[str]) -> list[str]:
    """把命令里的**宿主路径**重写为容器内可解析的形式（R-15）。

    两类需要重写：

    1. **宿主解释器路径**——`ctf_tools.json` 的 `{python}` 在配置装载时展开为
       `sys.executable`（如 `<PY312>\\python.exe`）。容器里
       那个路径不存在，镜像自带 python，用 `python`。
    2. **宿主工具二进制路径**——`external_tools.json` 写的
       `${PENTEST_TOOLS}/tools/nuclei.exe` 之类。镜像把这些工具的 Linux 版装到
       `/usr/local/bin`，容器内直接用**工具名**（靠 PATH 解析）。

    其它参数（目标、选项）原样保留——不做通用路径替换，那会把"镜像里没装
    这个工具"的错误藏起来，而它本该以 `command not found` 的形式暴露。
    """
    host_python = os.path.normcase(os.path.normpath(sys.executable))
    out = []
    for part in command:
        text = str(part)
        if os.path.normcase(os.path.normpath(text)) == host_python:
            out.append("python")
            continue
        tool = _basename_no_exe(text)
        out.append(tool or text)
    return out


class DockerRunner:
    """Docker 执行器：可用性探测（带缓存）+ 命令包装。"""

    level = "docker"

    def __init__(self, image: str = "", probe_timeout: float = 8.0) -> None:
        self.image = image or os.environ.get("PENTEST_DOCKER_IMAGE", DEFAULT_IMAGE)
        self.probe_timeout = probe_timeout
        self._probe: Optional[tuple[bool, str]] = None

    def available(self) -> tuple[bool, str]:
        """探测 docker CLI 与守护进程（结果缓存，避免每次执行都探测）。"""
        if self._probe is not None:
            return self._probe
        exe = shutil.which("docker")
        if not exe:
            self._probe = (False, "docker CLI 未安装或不在 PATH")
            return self._probe
        try:
            proc = subprocess.run(
                [exe, "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=self.probe_timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._probe = (False, f"docker 探测失败: {exc}")
            return self._probe
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            self._probe = (False, "docker 守护进程不可用: "
                                 + (detail[-1][:160] if detail else "未知原因"))
            return self._probe
        self._probe = (True, "")
        return self._probe

    def wrap(self, command: list[str], spec) -> list[str]:
        """把宿主命令包成容器命令：挂载工作目录，默认断网。

        **容器只认 Linux 路径**：`-w` 传宿主路径在 Windows 上必然失败——
        实测 `-w 'D:\\proj'` 得到 docker returncode 125
        `the working directory 'D:\\proj' is invalid`。所以宿主路径只用于
        `-v` 的**宿主侧**，容器侧固定映射到 `CONTAINER_WORKDIR`，`-w` 也用它。

        这个缺陷此前被掩盖：Docker 不可用时 `decide()` 直接拒绝，根本走不到
        这里；Docker 恢复后才暴露（见 docs/修复待办清单.md R-11 复核）。
        """
        host_dir = str(getattr(spec, "workdir", "") or "") or os.getcwd()
        return [shutil.which("docker") or "docker", "run", "--rm", "-i",
                "--network", self.network_mode(spec),
                "-v", f"{host_dir}:{CONTAINER_WORKDIR}",
                "-w", CONTAINER_WORKDIR,
                self.image, *containerize_command(command)]

    def network_mode(self, spec) -> str:
        """默认断网；工具显式声明需要出网时才给 bridge。"""
        if bool(getattr(spec, "network", False)):
            return "bridge"
        return "none"


class SandboxPolicy:
    """按模式的 sandbox 档位裁决每次工具执行。

    egress：模式 scope.network_egress 的消费端（False 为主）。关闭时，
    任何声明 network=True 的工具在**沙箱层**即被拒绝——与 Policy 闸门的
    出网裁决互为冗余（闸门覆盖无沙箱的构造路径，这里覆盖无闸门的路径），
    两道都在工具体执行前生效（硬规则 1）。
    """

    def __init__(self, level: str = "none",
                 runner: Optional[DockerRunner] = None,
                 egress: bool = False) -> None:
        normalized = (level or "none").strip().lower()
        if normalized not in LEVELS:
            raise ValueError(f"未知沙箱档位 {level!r}（可用 {LEVELS}）")
        self.level = normalized
        self.runner = runner or DockerRunner()
        self.egress = bool(egress)

    # ------------------------------------------------------------------
    def availability(self) -> tuple[bool, str]:
        """当前档位能否提供所需隔离（none/local 恒为可用）。"""
        if self.level == "docker":
            return self.runner.available()
        return True, ""

    def decide(self, spec) -> SandboxDecision:
        """执行前裁决：返回是否放行、原因、是否进容器。"""
        if getattr(spec, "network", False) and not self.egress:
            return SandboxDecision(
                False,
                f"模式关闭网络出口（scope.network_egress=false）："
                f"{spec.name} 声明需要出网，拒绝执行")

        needs_isolation = tool_needs_isolation(spec)

        if not needs_isolation:
            return SandboxDecision(True)          # 被动工具：三档都直接跑

        if self.level == "none":
            return SandboxDecision(
                False,
                f"sandbox=none 仅允许被动工具，{spec.name} 需要隔离执行；"
                f"请在模式中改用 sandbox: local（宿主直跑）或 sandbox: docker")

        if self.level == "local":
            # 宿主直跑：仍受 Policy 白名单与授权档位约束（调用方负责）
            return SandboxDecision(True, "sandbox=local：宿主直跑（已过白名单/授权）")

        # level == docker
        if getattr(spec, "kind", "") != "cli":
            return SandboxDecision(
                False,
                f"{spec.name} 需要隔离但类型为 {spec.kind}，无法进容器执行；"
                f"请改用 CLI 工具或调整模式 sandbox 档位")
        ok, reason = self.runner.available()
        if not ok:
            # 错误消息含可操作的修复指引（R-11 / ADR 配套约定 1）：
            # 只报"容器不可用"会让人卡住，而 ADR 明确要求"报明确错误
            # （含修复指引）"。指引只指向**显式降档**（sandbox: local）——
            # 静默降级是被否决的备选 A，运行期绝不自动回退。
            return SandboxDecision(
                False,
                f"sandbox=docker 但容器不可用（{reason}），拒绝裸跑 {spec.name}。"
                f"修复：启动 Docker 守护进程后重试（Windows 可启动 Docker "
                f"Desktop，或用 wsl --status 检查 WSL 后端）；确需在无容器"
                f"环境运行，请按 docs/沙箱降级评估.md 在模式文件中显式改为 "
                f"sandbox: local（宿主直跑，仍过白名单与权限档位）。"
                f"运行期不做静默降级")
        return SandboxDecision(True, "sandbox=docker：容器内执行", isolated=True,
                               wrap=lambda cmd, _spec=spec: self.runner.wrap(cmd, _spec))


def build_sandbox(level: str, runner: Optional[DockerRunner] = None,
                  egress: bool = False) -> SandboxPolicy:
    """按模式声明构造沙箱策略（egress 来自 mode.scope.network_egress）。"""
    return SandboxPolicy(level=level, runner=runner, egress=egress)