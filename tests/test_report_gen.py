"""R-45 回归：`report_gen` 在 `data_dir` 为空时不得 NameError。

历史缺陷：`penagent/builtin_tools.py` 的 `report_gen` 在调用方不传 `data_dir`
时回退到 `DATA_DIR`，但该符号只定义在 `penagent/http_session.py`，`builtin_tools`
模块作用域里没有——凡经 MCP（preset）调用 `report_gen` 必报
`name 'DATA_DIR' is not defined`。修复为函数内从 `http_session` 懒加载。
"""

from __future__ import annotations

from penagent import builtin_tools


def test_report_gen_default_data_dir_no_nameerror() -> None:
    result = builtin_tools.report_gen(format="markdown")
    assert result["ok"] is True
    assert result.get("chars", 0) >= 0


def test_report_gen_sarif_default_data_dir_no_nameerror() -> None:
    result = builtin_tools.report_gen(format="sarif")
    assert result["ok"] is True
