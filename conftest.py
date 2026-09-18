"""pytest 会话配置：解析外部依赖 07-agent-war-range 的位置。

内核的回归评测脚本（examples/*.py）需要 07 靶场的 warfare 仿真包。
按项目约定（AGENTS.md 第 7 条），外部项目按绝对路径引用、不做 vendoring。

路径优先级：
  1. 环境变量 PENTEST_G07_ROOT
  2. 相邻项目布局（内核置于 07 同级的开发目录时）
  3. 本机已知绝对路径

解析结果同时注入 PYTHONPATH，供 tests 以 subprocess 拉起的评测脚本继承。
"""
import os
import sys
from pathlib import Path

import pytest

from penagent.envcfg import load_env_file

# 本机路径只来自不入库的 .env（公开仓库零本机路径约定，见 penagent/envcfg.py）
load_env_file()

ROOT = Path(__file__).resolve().parent

CANDIDATES = [
    ROOT.parent / "07-agent-war-range",
    ROOT.parent / "网安项目开发规划" / "07-agent-war-range",
]


def _resolve_g07() -> "Path | None":
    env = os.environ.get("PENTEST_G07_ROOT")
    if env and (Path(env) / "warfare").is_dir():
        return Path(env)
    for candidate in CANDIDATES:
        if (candidate / "warfare").is_dir():
            return candidate
    return None


G07 = _resolve_g07()

if G07 is not None:
    if str(G07) not in sys.path:
        sys.path.insert(0, str(G07))
    _existing = os.environ.get("PYTHONPATH", "")
    _parts = [str(G07)] + ([_existing] if _existing else [])
    os.environ["PYTHONPATH"] = os.pathsep.join(_parts)

# 本机找不到 07 靶场时（CI / 新机器），依赖 warfare 包的直跑评测用例自动跳过，
# 其余用例照常执行。设 PENTEST_G07_ROOT 指向 07-agent-war-range 即可恢复。
G07_DEPENDENT_NODEIDS = {
    "tests/test_closed_loop.py::test_evaluate_uses_independent_hosts",
    "tests/test_m3.py::test_evolution_eval_script",
    "tests/test_m3.py::test_evolution_llm_script_mock",
    "tests/test_rl.py::test_train_script_runs",
}


def pytest_collection_modifyitems(config, items):
    if G07 is not None:
        return
    skip = pytest.mark.skip(
        reason="需要 07 靶场 warfare 包（设 PENTEST_G07_ROOT 指向 07-agent-war-range 后可用）")
    for item in items:
        if item.nodeid in G07_DEPENDENT_NODEIDS:
            item.add_marker(skip)


# ----------------------------------------------------------------------
# 测试注入：把内核注册表的沙箱档位钉成 local
# ----------------------------------------------------------------------
@pytest.fixture()
def host_direct_sandbox(monkeypatch):
    """让走内核构造路径的代码用 **local 档**沙箱建注册表。

    出厂 ctf-* 模式已声明 `sandbox: docker`（python_solve 等价宿主任意代码执行，
    容器不可用时必须被拒绝、绝不回落裸跑——见 docs/Web真内核实测记录.md F7）。
    本 fixture 只为一件事：让"解题链路"与 Web scripted 演示路径仍被**真跑**
    覆盖——显式注入操作员自选的 local 档（宿主直跑），而不是把用例改成 skip。

    无 Docker 环境下出厂模式的行为，由
    tests/test_sandbox.py::test_python_solve_refused_without_container_through_ctf_mode
    钉住；两者不冲突：一个测"拒绝"，一个测"链路本身没坏"。
    """
    import penagent.registry as registry_mod
    from penagent.sandbox import build_sandbox

    real_build_center = registry_mod.build_center

    class _HostDirectCenter:
        """包装注册中心：build_registry 强制 local 档（测试注入用）。"""

        def __init__(self, center):
            self._center = center

        def build_registry(self, mode=None, *, kernel_only=True, sandbox=None):
            return self._center.build_registry(
                mode, kernel_only=kernel_only, sandbox=build_sandbox("local"))

        def __getattr__(self, name):
            return getattr(self._center, name)

    def _patched():
        return _HostDirectCenter(real_build_center())

    monkeypatch.setattr(registry_mod, "build_center", _patched)
    # 模块级 `from ... import build_center` 的调用方持有自己的引用，一并替换
    for module_name in ("eval_ctf_solve",):
        module = sys.modules.get(module_name)
        if module is not None and hasattr(module, "build_center"):
            monkeypatch.setattr(module, "build_center", _patched)
