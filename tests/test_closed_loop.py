"""闭环回归评测测试。"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest


def test_closed_loop_script():
    """闭环回归评测可运行：四层策略对比输出收益链。"""
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "examples"
                            / "eval_closed_loop.py")],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=300)
    assert proc.returncode == 0, proc.stderr[-500:]
    out = proc.stdout
    assert "PPO" in out
    assert "47%" in out or "39%" in out      # 步数收益（PPO / Q）
    assert "83%" in out                      # 成功率（均衡分布环境上限）
    assert "80%" in out                      # PPO 原始成功率（分层后追平 Q）


def test_evaluate_uses_independent_hosts(tmp_path):
    """同一 host 对象被 exploit 污染后二次执行更快——评估须用副本。"""
    import copy

    sys.path.insert(0, str(PROJECT_ROOT / "examples"))
    from train_policy import SKILLS, execute_episode, make_host
    import random

    rng = random.Random(7)
    host = make_host(rng)
    seq = SKILLS["full-recon"][1]
    s1, ok1 = execute_episode(host, seq)            # 首次：正常步数
    s2, ok2 = execute_episode(host, seq)            # 二次：状态被污染
    assert s1 > s2 and ok1 and ok2                  # 污染导致"更快"（失真）
    s3, ok3 = execute_episode(copy.deepcopy(host), seq)  # 副本仍是污染态
    assert s3 == s2
