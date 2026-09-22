"""沙箱分级执行测试。

覆盖三档行为与降级路径：
- none ：仅被动工具放行；需要隔离的工具被拒绝
- local：需要隔离的工具宿主直跑（仍受 Policy 约束）
- docker：需要隔离的工具进容器；容器不可用时**拒绝执行且绝不裸跑**
- 模式接线：注册表按模式挂沙箱策略；模式声明非法档位被拒
"""
import os
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


def test_containerize_command_maps_host_tool_path_to_name():
    """宿主工具二进制路径（`.../nuclei.exe`）→ 容器内工具名。

    这是 R-15 渗透侧的核心：external_tools.json 写的是宿主绝对路径
    （`${PENTEST_TOOLS}/tools/nuclei.exe`），容器里不存在；镜像把 Linux 版
    装到 PATH，所以映射成工具名即可解析。
    """
    from penagent.sandbox import containerize_command

    cmd = containerize_command([r"C:\Tools\bin\nuclei.exe", "-u", "http://x"])
    assert cmd == ["nuclei", "-u", "http://x"]


def test_containerize_command_keeps_bare_names_and_args():
    """裸工具名与普通参数原样保留（不做通用路径替换——那会藏起错误）。"""
    from penagent.sandbox import containerize_command

    cmd = containerize_command(["sqlmap", "-u", "http://x", "--batch"])
    assert cmd == ["sqlmap", "-u", "http://x", "--batch"]
    # 非可执行参数（目标 URL、字典路径）不得被改写
    cmd2 = containerize_command(["ffuf", "-u", "http://a/FUZZ",
                                 "-w", r"C:\dicts\10k.txt"])
    assert cmd2 == ["ffuf", "-u", "http://a/FUZZ", "-w", r"C:\dicts\10k.txt"]


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


def _sandbox_image_or_skip():
    """取专用镜像的 runner（容器/镜像不可用时跳过）。"""
    image = "proteus-sandbox:latest"
    runner = DockerRunner(image=image, probe_timeout=8.0)
    ok, reason = runner.available()
    if not ok:
        pytest.skip(f"容器不可用: {reason}")
    if not _image_exists(image):
        pytest.skip(f"沙箱专用镜像未构建（docker build -f "
                    f"docker/Dockerfile.sandbox -t {image} docker/）")
    return runner


def test_sandbox_image_runs_rsactftool():
    """沙箱专用镜像内能跑 RsaCtfTool，且**用生产调用形态**。

    生产形态是 `{python} -m RsaCtfTool ...`（见 penagent/ctf_tools.json 的
    command）。此处显式用同一形态，而不是 `python -c "import RsaCtfTool"`
    ——后者只证明包可导入，对真实调用路径零覆盖。
    """
    runner = _sandbox_image_or_skip()
    spec = ToolSpec(name="rsa_probe", kind="cli", dangerous=True, timeout=120,
                    command=[sys.executable, "-m", "RsaCtfTool", "--help"],
                    workdir=".")
    registry = ToolRegistry(sandbox=build_sandbox("docker", runner=runner))
    registry.register(spec)

    result = registry.execute("rsa_probe", {})
    assert result.ok, f"容器内执行失败: {str(result.error)[:200]}"
    out = str(result.output).lower()
    assert "--publickey" in out and "help" in out, \
        f"RsaCtfTool 未按生产形态运行: {str(result.output)[:120]}"


def test_sandbox_image_runs_sqlmap_through_command_rewrite():
    """渗透工具的完整容器化链路（R-15 渗透侧）。

    覆盖三件事同时生效：
    1. `containerize_command` 把宿主 `.exe` 路径重写为容器内工具名；
    2. 镜像内确实装了这个工具（docker/Dockerfile.sandbox）；
    3. 执行走的是**生产路径** `ToolRegistry.execute` → 沙箱裁决 → 容器。

    路径写成宿主形态（含目录 + `.exe`）——那正是 external_tools.json 里的
    实际写法，不能简化成裸名否则测不到重写逻辑。

    `egress=True`：出网工具在 `network_egress=false` 的模式下会被沙箱拒绝
    （R-16 的机制，现仍保留——pentest-standard 已于 2026-09-21 决策改声明
    `network_egress: true`，但 base 模式与其他模式仍可关闸）。这里测的是
    **容器化链路本身**，故显式放开出网。
    """
    runner = _sandbox_image_or_skip()
    # 工具路径从环境解析（本机路径不入库，硬规则 7）；未配置时用合成路径。
    # 两者都必须是**绝对路径 + .exe**，否则测不到 containerize_command 的重写
    tools_root = Path(os.environ.get("PENTEST_TOOLS") or r"C:\path\to\tools")
    spec = ToolSpec(name="sqlmap_probe", kind="cli", dangerous=True,
                    network=True, timeout=120, workdir=".",
                    command=[str(tools_root / "tools" / "sqlmap.exe"),
                             "--version"])
    registry = ToolRegistry(
        sandbox=build_sandbox("docker", runner=runner, egress=True))
    registry.register(spec)

    result = registry.execute("sqlmap_probe", {})
    assert result.ok, f"容器内执行失败: {str(result.error)[:200]}"
    assert "#pip" in str(result.output), \
        f"未取到 sqlmap 版本: {str(result.output)[:120]}"


def _juiceshop_reachable() -> bool:
    """探测宿主侧 Juice Shop 是否存活。

    目标被约束为硬编码的 `http://127.0.0.1:3000`（协议 + 主机白名单 +
    解析 IP 必须为环回），满足 Mimosa 对 SSRF 的边界要求——测试靶场
    只允许打本机环回，任何其他目标一律拒绝。
    """
    import ipaddress
    import socket
    import urllib.request

    if not all(ipaddress.ip_address(i[4][0]).is_loopback
               for i in socket.getaddrinfo("127.0.0.1", 3000,
                                           type=socket.SOCK_STREAM)):
        return False
    try:
        with urllib.request.urlopen("http://127.0.0.1:3000", timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


def test_sandbox_sqlmap_real_scan_against_juiceshop():
    """容器内 sqlmap **真扫**宿主靶场（R-15 真实证据的回归固化）。

    与上一条只验 `--version` 不同，本条要求容器内的 sqlmap 对宿主上的
    Juice Shop 发起真实注入探测。三个前置，任一不满足即跳过而非失败：
    - 专用镜像就绪（`_sandbox_image_or_skip`）；
    - 宿主 Juice Shop 在 3000 端口存活；
    - 出网已放开（容器内 `127.0.0.1` 是容器自己，必须走
      `host.docker.internal`，见 docs/修复待办清单.md R-15 第二轮）。

    断言取 sqlmap 探测过程中的两个稳定标记（连接测试 + 参数动态判定），
    不依赖注入是否成功——靶场的响应随版本演进，注入结论不稳，但
    "真的在扫"这个行为是稳的。
    """
    runner = _sandbox_image_or_skip()
    if not _juiceshop_reachable():
        pytest.skip("Juice Shop 靶场未运行（docker run --name rx-juiceshop "
                    "-p 3000:3000 bkimminich/juice-shop）")

    spec = ToolSpec(name="sqlmap_scan", kind="cli", dangerous=True,
                    network=True, timeout=300, workdir=".",
                    command=["sqlmap",
                             "-u",
                             "http://host.docker.internal:3000/rest/products/"
                             "search?q=test",
                             "--batch", "--level", "1", "--risk", "1",
                             "--threads", "4"])
    registry = ToolRegistry(
        sandbox=build_sandbox("docker", runner=runner, egress=True))
    registry.register(spec)

    result = registry.execute("sqlmap_scan", {})
    assert result.ok, f"容器内 sqlmap 执行失败: {str(result.error)[:200]}"
    out = str(result.output)
    assert "testing connection to the target URL" in out, \
        f"sqlmap 未对目标发起连接测试: {out[:200]}"
    assert "appears to be dynamic" in out or "could be injectable" in out, \
        f"sqlmap 未完成参数动态判定: {out[:200]}"


# ----------------------------------------------------------------------
# Go 工具（R-15 第三轮：镜像纳入 fscan / naabu / dalfox）
# ----------------------------------------------------------------------
@pytest.fixture
def reflector_target():
    """宿主侧"反射型靶页"服务（Go 工具容器内真扫的自带靶标）。

    容器里的 `127.0.0.1` 是容器自己，只能经 `host.docker.internal` 回宿主，
    故这里在宿主上起一个临时端口的回显页（把查询串原样写进 HTML）。

    返回 `(ip, port)`：IP 由容器内解析一次后**显式传给工具**，不把
    hostname 丢给工具自己解析——实测容器内 `/etc/hosts` 并无
    `host.docker.internal` 条目（只有 localhost 与本机名），该名字靠 Docker
    的 DNS（192.168.65.7）解析，naabu 自带解析器对它约一半的运行直接报
    `no valid ipv4 or ipv6 targets were found`（实测抖动）。解析一次、
    传 IP，用例才是确定性的。不可达时 skip——环境差异不该表现为失败。
    """
    import http.server
    import threading
    import urllib.parse

    runner = _sandbox_image_or_skip()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.urlparse(self.path).query
            body = ("<html><body><h1>search</h1>"
                    f"<div id='r'>{q}</div></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def _in_container(code: str, *extra: str):
        import subprocess

        return subprocess.run(
            ["docker", "run", "--rm", "--network", "bridge", runner.image,
             "python", "-c", code, *extra],
            capture_output=True, text=True, timeout=60)

    try:
        probe = _in_container(
            "import socket,sys;"
            "ip = socket.gethostbyname('host.docker.internal');"
            "socket.create_connection((ip, int(sys.argv[1])), 5);"
            "print('reachable', ip)", str(port))
        if "reachable" not in probe.stdout:
            pytest.skip(f"容器无法访问宿主靶页（{probe.stdout.strip()} "
                        f"{probe.stderr.strip()[:120]}）")
        yield probe.stdout.split()[-1], port
    finally:
        server.shutdown()
        server.server_close()


def test_sandbox_image_has_go_tools():
    """镜像内三个 Go 工具就位（各自报版本）。

    这条防的是"镜像重建时漏装/装错架构"；"真的能扫"的证据在下面三条真扫
    用例里，不在版本号上。
    """
    runner = _sandbox_image_or_skip()
    spec = ToolSpec(name="go_tools_probe", kind="cli", dangerous=True,
                    timeout=120, workdir=".",
                    command=["sh", "-c",
                             "naabu -version 2>&1; "
                             "dalfox version 2>&1 | grep -m1 -i dalfox; "
                             "fscan 2>&1 | head -20"])
    registry = ToolRegistry(sandbox=build_sandbox("docker", runner=runner))
    registry.register(spec)

    result = registry.execute("go_tools_probe", {})
    assert result.ok, f"容器内执行失败: {str(result.error)[:200]}"
    out = str(result.output).lower()
    # naabu 的版本行是 "Current Version: x.y.z"（banner 在 stderr，无工具名）
    assert "current version" in out, f"naabu 未就位于镜像: {str(result.output)[:200]}"
    for name in ("dalfox", "fscan"):
        assert name in out, f"{name} 未就位于镜像: {str(result.output)[:200]}"


def test_sandbox_fscan_real_scan_uses_registry_spec(tmp_path):
    """fscan 按**注册表真实配置**在容器内真扫宿主。

    直接取 external_tools.json 的 `fscan_scan` spec 执行，故一条用例同时
    覆盖：① 宿主 `.exe` 路径 → 容器内工具名的重写；② 镜像内确有 fscan；
    ③ 容器经 host.docker.internal 打到宿主端口。

    靶标取宿主 8080（DVWA）——它恰在 spec 的 `-p` 端口列表内。靶场未运行时
    跳过，不把环境缺失算作失败。

    `workdir` 换成 tmp_path：fscan 默认在**工作目录**写 `result.txt`
    （实测），不换就把测试产物落进仓库根了。
    """
    import socket
    from dataclasses import replace

    runner = _sandbox_image_or_skip()
    try:
        with socket.create_connection(("127.0.0.1", 8080), timeout=3):
            pass
    except OSError:
        pytest.skip("宿主 8080（DVWA）未运行，跳过 fscan 真扫用例")

    from penagent.external_tools import load_external_tools

    base = ToolRegistry()
    load_external_tools(base)
    spec = base.get("fscan_scan")
    if spec is None:
        pytest.skip("fscan 未在本地注册（${PENTEST_TOOLS}/tools/fscan.exe 缺失）")
    spec = replace(spec, workdir=str(tmp_path))

    registry = ToolRegistry(
        sandbox=build_sandbox("docker", runner=runner, egress=True))
    registry.register(spec)

    result = registry.execute("fscan_scan", {"host": "host.docker.internal"})
    assert result.ok, f"容器内 fscan 执行失败: {str(result.error)[:200]}"
    out = str(result.output)
    assert "8080" in out and "扫描任务完成" in out, \
        f"fscan 未在容器内真扫: {out[:200]}"


def test_sandbox_naabu_real_scan_finds_open_port(reflector_target):
    """naabu 在容器内经生产路径真扫宿主端口（扫描结果自证）。

    参数形态与 external_tools.json 的 `naabu_scan` 一致（含 `-sr` 系统解析
    兜底）；靶标用 fixture 解析出的 IP 而非 hostname——原因见 fixture
    docstring（naabu 自带解析器解析 Docker 特殊名不稳）。
    """
    ip, port = reflector_target
    runner = _sandbox_image_or_skip()
    spec = ToolSpec(name="naabu_probe", kind="cli", dangerous=True,
                    network=True, timeout=120, workdir=".",
                    command=["naabu", "-host", ip, "-p", str(port),
                             "-sr", "-silent"])
    registry = ToolRegistry(
        sandbox=build_sandbox("docker", runner=runner, egress=True))
    registry.register(spec)

    result = registry.execute("naabu_probe", {})
    assert result.ok, f"容器内 naabu 执行失败: {str(result.error)[:200]}"
    assert f":{port}" in str(result.output), \
        f"naabu 未扫到靶页端口: {str(result.output)[:200]}"


def test_sandbox_dalfox_real_scan_finds_reflection(reflector_target):
    """dalfox 在容器内真扫：识别反射点并产出 POC。

    用注册表 spec 的**真实命令形态**（`dalfox url --url <target>`——v3.2.0
    的必需写法；修正前的 `dalfox url <target>` 在 v3.2.0 上直接报
    `--url <URL> not provided`）。只去掉 `--silence`：它是生产形态的降噪
    选择，不改调用语义，但会把输出全部抑制导致无法断言。

    **不看 `result.ok`**：dalfox 的退出码语义是"有发现则非 0"（实测：找到
    POC 时 exit=1，无发现时 exit=0），故这里的成败只能由输出判定。
    """
    from dataclasses import replace

    ip, port = reflector_target
    runner = _sandbox_image_or_skip()
    from penagent.external_tools import load_external_tools

    base = ToolRegistry()
    load_external_tools(base)
    spec = base.get("dalfox_xss")
    if spec is None:
        pytest.skip("dalfox 未在本地注册（${PENTEST_TOOLS}/tools/dalfox.exe 缺失）")

    probe = replace(spec, name="dalfox_probe",
                    command=[c for c in spec.command if c != "--silence"])
    registry = ToolRegistry(
        sandbox=build_sandbox("docker", runner=runner, egress=True))
    registry.register(probe)

    result = registry.execute(
        "dalfox_probe", {"url": f"http://{ip}:{port}/search?q=test"})
    out = str(result.output)
    assert "found reflected" in out, f"dalfox 未完成反射分析: {out[:200]}"
    assert "Payload:" in out, f"dalfox 未产出 POC: {out[:200]}"


def test_egress_off_blocks_networked_tool_before_container():
    """`network_egress=false` 时出网工具被**沙箱层**拒绝（R-16 的机制）。

    钉住该机制本身：渗透工具本质需要出网，pentest-standard 已于
    2026-09-21 决策改为 `network_egress: true`（R-16 选①），但该闸门
    机制保留——base 缺省仍是 false，其他模式可按需关闸。
    """
    spec = ToolSpec(name="net_tool", kind="cli", dangerous=True,
                    network=True, command=["echo", "x"])
    registry = ToolRegistry(sandbox=build_sandbox("docker", egress=False))
    registry.register(spec)

    result = registry.execute("net_tool", {})
    assert not result.ok
    assert "网络出口" in result.error
