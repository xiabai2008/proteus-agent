"""会话授权目标（P0-4，2026-09-24 拍板 D4）。

设计：

- **永久授权 = 人工命令**：`/proteus-scope`（DSH 命令插件）或
  `python -m penagent scope --add <host>` 写 `data/session-scope.json`；
- **一次性放行 = 审批卡**：越界目标在内核侧一律拒绝，错误信息带授权指引；
  宿主侧由 DSH 的 approval 档位与目标动作裁决行承担；
- **模型不能自我授权**：内核**从不**写这个文件。写入口只有 CLI 与命令插件
  （都是人能看见的动作）。运行期只有读。

与 `--targets` 的关系：`--targets` 是**操作员级基线**（启动时设定，缺省回环），
会话授权是**在同一进程里追加的人工授权**——两者取并集。硬规则 3 不变：
白名单仍然硬校验，只是白名单本身可以由人显式扩大。

文件格式（`data/session-scope.json`）：

```json
{"targets": ["example.com", "10.0.0.5"], "updated_at": "2026-09-24 12:00:00",
 "note": "授权来源说明（人写，便于事后审计）"}
```

读失败（缺失/损坏/类型不对）一律回落到空清单——**不阻塞**任务，也不静默放行
（空清单 = 只有 `--targets` 基线生效）。
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable, Union

SESSION_SCOPE_FILE = "session-scope.json"

Targets = Union[str, Iterable[str], None]


def scope_path(data_dir: Union[str, Path]) -> Path:
    return Path(data_dir) / SESSION_SCOPE_FILE


def _normalize(targets: Targets) -> list[str]:
    """逗号分隔字符串 / 可迭代 → 去重保序的小写条目列表（保持原样大小写）。

    只做去重与去空，不做域名合法性判断——白名单匹配是子串式
    （`host.endswith("." + t)`），非法条目最多是永不命中，不会放宽。
    """
    if targets is None:
        return []
    if isinstance(targets, str):
        items = targets.split(",")
    else:
        items = list(targets)
    seen: list[str] = []
    for item in items:
        text = str(item).strip()
        if text and text not in seen:
            seen.append(text)
    return seen


def read_scope(data_dir: Union[str, Path]) -> list[str]:
    """读会话授权清单（缺失/损坏 → 空清单，不抛异常）。"""
    try:
        data = json.loads(scope_path(data_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    return _normalize(data.get("targets"))


def write_scope(data_dir: Union[str, Path], targets: Targets, *,
                note: str = "") -> list[str]:
    """整体覆盖会话授权清单（幂等），返回写入后的清单。"""
    path = scope_path(data_dir)
    clean = _normalize(targets)
    payload = {"targets": clean,
               "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
               "note": str(note)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return clean


def add_targets(data_dir: Union[str, Path], targets: Targets, *,
                note: str = "") -> list[str]:
    """追加授权（去重）；返回新清单。"""
    merged = read_scope(data_dir)
    for item in _normalize(targets):
        if item not in merged:
            merged.append(item)
    return write_scope(data_dir, merged, note=note)


def remove_targets(data_dir: Union[str, Path], targets: Targets) -> list[str]:
    """移除授权；返回新清单。"""
    drop = {t.lower() for t in _normalize(targets)}
    kept = [t for t in read_scope(data_dir) if t.lower() not in drop]
    return write_scope(data_dir, kept)


def clear_scope(data_dir: Union[str, Path]) -> list[str]:
    """清空会话授权（回到只剩 `--targets` 基线）。"""
    return write_scope(data_dir, [])
