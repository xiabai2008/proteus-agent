"""沙箱分级执行测试。

覆盖三档行为与降级路径：
- none ：仅被动工具放行；需要隔离的工具被拒绝
- local：需要隔离的工具宿主直跑（仍受 Policy 约束）
- docker：需要隔离的工具进容器；容器不可用时**拒绝执行且绝不裸跑**
- 模式接线：注册表按模式挂沙箱策略；模式声明非法档位被拒
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.modes import ModeError, load_mode
from penagent.registry import build_center
from penagent.sandbox import (LEVELS, DockerRunner, SandboxPolicy,
                              build_sandbox, tool_needs_isolation)
from penagent.tools import ToolRegistry, ToolSpec


class StubRunner:
    """可注入的容器执行器：记录包装调用，按需声明可用/不可用。"""

    def __init__(self, available: bool = True) -> None:
        self._available = available
        self.wrapped: list[list[str]] = []

    def available(self) -> tuple[bool, str]:
        return (True, "") if self._available else (False, "守护进程未运行（桩）")

    def wrap(self, command: list[str], spec) -> list[str]:
        self.wrapped.append(list(command))
        return list(command)          # 桩：原样返回，验证"本会进容器"


def _marker_code(root: Path, name: str = "ran.txt") -> str:
    """生成"写入标记文件"的脚本代码，用于验证工具到底有没有被执行。

    路径先规范化并限定在 root 目录内——越界直接报错，避免把外部路径
    拼进被测命令。
    """
    root = Path(root).resolve()
    target = (root / name).resolve()
    if target.parent != root:
        raise ValueError(f"标记文件必须位于测试目录内: {target}")
    return (f"import pathlib; pathlib.Path({str(target)!r})"
            f".write_text('ran', encoding='utf-8')")


def _cli_tool(*, dangerous: bool, code: str = "",
              sandbox: str = "") -> ToolSpec:
    return ToolSpec(name="script_run", description="一次性脚本",
                    kind="cli",
                    command=[sys.executable, "-c", code or "print('sandbox-ok')"],
                    dangerous=dangerous, sandbox=sandbox, timeout=30)


def _passive_tool() -> ToolSpec:
    return ToolSpec(name="http_probe", description="被动探测",
                    parameters={"url": {"type": "string"}},
                    fn=lambda **kw: {"status": 200})


# ----------------------------------------------------------------------
# 1. 档位行为矩阵
# ----------------------------------------------------------------------
def test_none_level_allows_passive_but_refuses_isolated():
    registry = ToolRegistry(sandbox=build_sandbox("none"))
    registry.register(_passive_tool())
    registry.register(_cli_tool(dangerous=True))

    assert registry.execute("http_probe", {"url": "http://127.0.0.1"}).ok
    refused = registry.execute("script_run", {})
    assert not refused.ok
    assert "sandbox=none" in refused.error and "需要隔离" in refused.error


def test_local_level_runs_isolated_tool_on_host():
    registry = ToolRegistry(sandbox=build_sandbox("local"))
    registry.register(_cli_tool(dangerous=True))

    result = registry.execute("script_run", {})
    assert result.ok and "sandbox-ok" in str(result.output)


def test_docker_level_wraps_isolated_tool():
    runner = StubRunner(available=True)
    registry = ToolRegistry(sandbox=build_sandbox("docker", runner=runner))
    registry.register(_cli_tool(dangerous=True))

    result = registry.execute("script_run", {})
    assert result.ok                                  # 桩容器"执行"成功
    assert runner.wrapped, "需要隔离的工具必须经过容器包装"
    assert "python" in Path(runner.wrapped[0][0]).name


def test_docker_level_passes_passive_tool_through():
    runner = StubRunner(available=True)
    registry = ToolRegistry(sandbox=build_sandbox("docker", runner=runner))
    registry.register(_passive_tool())
    registry.register(_cli_tool(dangerous=False))

    assert registry.execute("http_probe", {}).ok
    assert registry.execute("script_run", {}).ok
    assert runner.wrapped == []            # 被动工具不进容器


# ----------------------------------------------------------------------
# 2. 降级路径：容器不可用 -> 拒绝，绝不裸跑
# ----------------------------------------------------------------------
def test_docker_unavailable_refuses_and_never_runs_bare(tmp_path):
    marker = tmp_path / "ran.txt"
    runner = StubRunner(available=False)
    registry = ToolRegistry(sandbox=build_sandbox("docker", runner=runner))
    registry.register(_cli_tool(dangerous=True,
                                code=_marker_code(tmp_path)))

    result = registry.execute("script_run", {})
    assert not result.ok
    assert "容器不可用" in result.error and "拒绝裸跑" in result.error
    assert not marker.exists(), "容器不可用时绝不能降级为宿主直跑"


def test_docker_unavailable_message_carries_remediation():
    """容器不可用的错误必须**含修复指引**（R-11）。

    ADR（`docs/沙箱降级评估.md` 第二节备选 C 的配套约定 1）要求 docker 档在
    容器不可用时报明确错误**含修复指引**。本用例钉住这一点，防止退化成
    只报"坏了"却不说怎么修。指引必须指向**显式降档**（`sandbox: local`），
    不能暗示运行期静默回退——静默降级是被否决的备选 A。
    """
    runner = StubRunner(available=False)
    policy = build_sandbox("docker", runner=runner)
    decision = policy.decide(_cli_tool(dangerous=True))

    assert decision.allowed is False
    reason = decision.reason
    assert "拒绝裸跑" in reason            # 既有语义保持不变
    assert "sandbox: local" in reason      # 指向唯一的显式降档路径
    assert "沙箱降级评估" in reason        # 给出 ADR 依据，便于查证


def test_local_level_actually_executes_the_same_tool(tmp_path):
    """对照组：同一工具在 local 档确实会执行（证明上一条不是"命令本身跑不起来"）。"""
    marker = tmp_path / "ran.txt"
    registry = ToolRegistry(sandbox=build_sandbox("local"))
    registry.register(_cli_tool(dangerous=True, code=_marker_code(tmp_path)))

    assert registry.execute("script_run", {}).ok
    assert marker.exists()


def test_docker_level_refuses_non_cli_isolated_tool():
    """函数型工具无法进容器：需要隔离时拒绝，而不是就地执行。"""
    spec = ToolSpec(name="dangerous_fn", dangerous=True,
                    fn=lambda **kw: "executed")
    registry = ToolRegistry(sandbox=build_sandbox("docker",
                                                 runner=StubRunner(True)))
    registry.register(spec)
    result = registry.execute("dangerous_fn", {})
    assert not result.ok and "无法进容器执行" in result.error


def test_real_docker_probe_reports_reason():
    """真实环境探测：无论本机是否有 Docker，都要给出明确可用性结论。"""
    ok, reason = DockerRunner(probe_timeout=10.0).available()
    assert isinstance(ok, bool)
    if not ok:
        assert reason, "不可用时必须给出原因（供拒绝执行时展示）"


# ----------------------------------------------------------------------
# 3. 隔离需求判定与模式接线
# ----------------------------------------------------------------------
def test_isolation_requirement_rules():
    assert tool_needs_isolation(ToolSpec(name="a", dangerous=True)) is True
    assert tool_needs_isolation(ToolSpec(name="b", sandbox="docker")) is True
    assert tool_needs_isolation(ToolSpec(name="c")) is False
    assert tool_needs_isolation(ToolSpec(name="d", dangerous=False,
                                         sandbox="none")) is False


def test_registry_gets_sandbox_from_mode():
    center = build_center()
    pentest = center.build_registry(load_mode("pentest-standard"))
    assert pentest.sandbox.level == "docker"

    # CTF 模式声明 docker：解题脚本（python_solve）等价宿主任意代码执行，
    # 必须进容器；声明 local 等于放行裸跑（Web-F7 的根因）。
    assert center.build_registry(load_mode("ctf-crypto")).sandbox.level == "docker"
    assert center.build_registry(load_mode("ctf-web")).sandbox.level == "docker"


def test_mode_sandbox_field_validated(tmp_path):
    modes_dir = tmp_path / "modes"
    modes_dir.mkdir()
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "stub.md").write_text("模板", encoding="utf-8")
    (modes_dir / "bad.yaml").write_text(
        "id: bad\npersona: {system_prompt: prompts/stub.md}\n"
        "budget: {max_steps: 5}\nverifier: {type: evidence_chain}\n"
        "sandbox: virtualenv\n", encoding="utf-8")

    with pytest.raises(ModeError, match="sandbox"):
        load_mode("bad", modes_dir=modes_dir)
    assert set(LEVELS) == {"none", "local", "docker"}


def test_python_solve_declares_container_requirement():
    """CTF 解题脚本声明需要容器隔离：docker 档 + 无容器时被拒。"""
    center = build_center()
    entries = {e.name: e for e in center.discover(mode_id="ctf-crypto")}
    spec = entries["python_solve"].spec
    assert spec.sandbox == "docker"
    assert tool_needs_isolation(spec) is True

    runner = StubRunner(available=False)
    registry = ToolRegistry(sandbox=SandboxPolicy("docker", runner=runner))
    registry.register(spec)
    result = registry.execute("python_solve", {"code": "print(1)"})
    assert not result.ok and "拒绝裸跑" in result.error


def test_python_solve_refused_without_container_through_ctf_mode(tmp_path):
    """按 modes/*.yaml 的 sandbox 档位实装（Web-F7）。

    ctf-web 声明 sandbox: docker，本机容器不可用时 python_solve 必须被**拒绝**，
    而不是回落到宿主直跑——用标记文件证明脚本体一次都没执行。
    """
    marker = tmp_path / "ran.txt"
    mode = load_mode("ctf-web")
    runner = StubRunner(available=False)
    registry = build_center().build_registry(
        mode, sandbox=SandboxPolicy("docker", runner=runner))
    result = registry.execute("python_solve", {"code": _marker_code(tmp_path)})

    assert not result.ok
    assert "容器不可用" in result.error and "拒绝裸跑" in result.error
    assert not marker.exists(), "容器不可用时 python_solve 绝不能宿主直跑"


def test_python_solve_is_container_only_under_ctf_mode():
    """对照组：容器可用时该工具被判为"进容器"，控制路径上不留宿主直跑的口子。"""
    mode = load_mode("ctf-web")
    center = build_center()
    spec = {e.name: e for e in center.discover(mode_id="ctf-web")}["python_solve"].spec
    policy = SandboxPolicy("docker", runner=StubRunner(available=True))
    decision = policy.decide(spec)

    assert decision.allowed and decision.isolated is True
    assert mode.sandbox == "docker", "模式须声明 docker 档（local 等于放行裸跑）"

# ----------------------------------------------------------------------
# 2b. 容器内工作目录：宿主路径不能直接作 -w（R-11 复核发现）
#
# 容器只认 Linux 路径。此前 wrap() 把宿主路径同时用作 -v 的容器侧与 -w，
# 在 Windows 上必然失败（docker returncode 125，`the working directory
# 'D:\...' is invalid`）。该缺陷此前被掩盖：Docker 不可用时 decide() 直接
# 拒绝，走不到 wrap()；Docker 恢复后才暴露。
# ----------------------------------------------------------------------
def test_docker_wrap_uses_container_linux_workdir():
    """-w 必须是容器内的 Linux 路径；宿主路径只出现在 -v 的宿主侧。"""
    from penagent.sandbox import CONTAINER_WORKDIR

    spec = ToolSpec(name="t", kind="cli", dangerous=True, workdir=r"D:\proj")
    cmd = DockerRunner().wrap(["python", "-c", "x"], spec)

    w_idx = cmd.index("-w")
    assert cmd[w_idx + 1] == CONTAINER_WORKDIR, \
        f"-w 用了容器不认的路径: {cmd[w_idx + 1]!r}"
    v_idx = cmd.index("-v")
    assert cmd[v_idx + 1] == f"{spec.workdir}:{CONTAINER_WORKDIR}"


def test_docker_container_execution_actually_works(tmp_path):
    """端到端：包装后的命令在容器内**真跑**成功（容器不可用时跳过）。

    这条覆盖"裁决放行"之外的**真实执行**——正是它暴露出 -w 的路径缺陷：
    修复前该用例必然失败（返回码 125，工具体一次都没跑起来）。
    """
    runner = DockerRunner(probe_timeout=8.0)
    ok, reason = runner.available()
    if not ok:
        pytest.skip(f"容器不可用: {reason}")

    spec = ToolSpec(name="probe", kind="cli", dangerous=True, timeout=120,
                    command=["python", "-c", "print('container-ok')"],
                    workdir=str(tmp_path))
    registry = ToolRegistry(sandbox=build_sandbox("docker", runner=runner))
    registry.register(spec)

    result = registry.execute("probe", {})
    assert result.ok, f"容器内执行失败: {result.error[:200]}"
    assert "container-ok" in str(result.output)


# ----------------------------------------------------------------------
# 2c. 命令容器化：{python} 展开为宿主路径，容器内必须改成 python（R-15）
#
# ctf_tools.json 的 {python} 在配置装载时展开为 sys.executable（宿主绝对
# 路径）。宿主直跑没问题；容器里那个路径不存在——镜像自带 python。
# ----------------------------------------------------------------------
def test_containerize_command_rewrites_host_python():
    from penagent.sandbox import containerize_command

    cmd = containerize_command([sys.executable, "-m", "RsaCtfTool", "-n", "1"])
    assert cmd[0] == "python"
    assert cmd[1:] == ["-m", "RsaCtfTool", "-n", "1"]


def test_containerize_command_leaves_other_paths_alone():
    """只重写解释器路径——其它宿主路径无脑替换会把错误藏起来。"""
    from penagent.sandbox import containerize_command

    other = [r"C:\Tools\bin\nuclei.exe", "-u", "http://x"]
    assert containerize_command(other) == other


def test_wrap_contains_no_host_python_path():
    """wrap 产出的命令里不得残留宿主解释器路径。"""
    from penagent.sandbox import DockerRunner

    spec = ToolSpec(name="t", kind="cli", dangerous=True)
    cmd = DockerRunner().wrap([sys.executable, "-c", "print(1)"], spec)
    assert sys.executable not in cmd
    assert "python" in cmd


def _image_exists(name: str) -> bool:
    import subprocess

    proc = subprocess.run(["docker", "image", "inspect", name],
                          capture_output=True, text=True)
    return proc.returncode == 0


def test_sandbox_image_runs_rsactftool():
    """沙箱专用镜像内能跑 RsaCtfTool（R-15 的目标能力）。

    镜像未构建 / 容器不可用时跳过——那是环境缺失，不是缺陷。
    构建方式见 docker/Dockerfile.sandbox。
    """
    image = "proteus-sandbox:latest"
    runner = DockerRunner(image=image, probe_timeout=8.0)
    ok, reason = runner.available()
    if not ok:
        pytest.skip(f"容器不可用: {reason}")
    if not _image_exists(image):
        pytest.skip(f"沙箱专用镜像未构建（docker build -f "
                    f"docker/Dockerfile.sandbox -t {image} docker/）")

    spec = ToolSpec(name="rsa_probe", kind="cli", dangerous=True, timeout=120,
                    command=[sys.executable, "-c",
                             "import RsaCtfTool; print('rsactf-ready')"],
                    workdir=".")
    registry = ToolRegistry(sandbox=build_sandbox("docker", runner=runner))
    registry.register(spec)

    result = registry.execute("rsa_probe", {})
    assert result.ok, f"容器内执行失败: {str(result.error)[:200]}"
    assert "rsactf-ready" in str(result.output)
