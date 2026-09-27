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
from typing import Iterable, Optional, Union

SESSION_SCOPE_FILE = "session-scope.json"

Targets = Union[str, Iterable[str], None]


def _file_name(key: str = "") -> str:
    """按会话键分文件（P0-6）：三个 preset 共用 data/ 时不能互串。

    空键 = 旧行为（`session-scope.json`），单 preset 场景保持兼容。
    """
    key = str(key or "").strip()
    return f"session-scope-{key}.json" if key else SESSION_SCOPE_FILE


def scope_path(data_dir: Union[str, Path], key: str = "") -> Path:
    return Path(data_dir) / _file_name(key)


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


def read_scope(data_dir: Union[str, Path], key: str = "") -> list[str]:
    """读会话授权清单（缺失/损坏 → 空清单，不抛异常）。"""
    return _read_list(data_dir, key, "targets")


def read_reference(data_dir: Union[str, Path], key: str = "") -> list[str]:
    """读**只读参考站**名单（公开 WP / 知识库；缺失/损坏 → 空清单）。

    与 `targets` 的区别（2026-09-27 实测新增）：参考站只对**只读工具**
    放行（`is_read_only_call`：GET/HEAD 类读取），扫描/爆破/利用类工具永远
    只看 `targets`。这样"给人看 WP"不必把公开站点写进目标授权，也不会因为
    加了一个参考站而让攻击面工具够到它。
    """
    return _read_list(data_dir, key, "reference")


def _read_list(data_dir: Union[str, Path], key: str, field: str) -> list[str]:
    try:
        data = json.loads(scope_path(data_dir, key).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    return _normalize(data.get(field))


def write_scope(data_dir: Union[str, Path], targets: Targets, *,
                note: str = "", key: str = "",
                reference: Optional[Targets] = None) -> list[str]:
    """整体覆盖会话授权清单（幂等），返回写入后的清单。

    `reference=None` 时**保留**文件里既有的只读参考站名单——`write_scope` 的
    调用方（CLI 的 add/remove/clear）只该动自己那一类，不能顺手把另一类抹掉。
    """
    path = scope_path(data_dir, key)
    clean = _normalize(targets)
    ref = read_reference(data_dir, key) if reference is None \
        else _normalize(reference)
    payload = {"targets": clean,
               "reference": ref,
               "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
               "note": str(note)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return clean


def add_targets(data_dir: Union[str, Path], targets: Targets, *,
                note: str = "", key: str = "") -> list[str]:
    """追加授权（去重）；返回新清单。"""
    merged = read_scope(data_dir, key)
    for item in _normalize(targets):
        if item not in merged:
            merged.append(item)
    return write_scope(data_dir, merged, note=note, key=key)


def remove_targets(data_dir: Union[str, Path], targets: Targets,
                   key: str = "") -> list[str]:
    """移除授权；返回新清单。"""
    drop = {t.lower() for t in _normalize(targets)}
    kept = [t for t in read_scope(data_dir, key) if t.lower() not in drop]
    return write_scope(data_dir, kept, key=key)


def add_reference(data_dir: Union[str, Path], hosts: Targets, *,
                  note: str = "", key: str = "") -> list[str]:
    """追加只读参考站（去重）；返回新的参考站清单。"""
    merged = read_reference(data_dir, key)
    for item in _normalize(hosts):
        if item not in merged:
            merged.append(item)
    write_scope(data_dir, read_scope(data_dir, key), note=note, key=key,
                reference=merged)
    return merged


def remove_reference(data_dir: Union[str, Path], hosts: Targets,
                     key: str = "") -> list[str]:
    """移除只读参考站；返回新清单。"""
    drop = {t.lower() for t in _normalize(hosts)}
    kept = [t for t in read_reference(data_dir, key) if t.lower() not in drop]
    write_scope(data_dir, read_scope(data_dir, key), key=key, reference=kept)
    return kept


def clear_scope(data_dir: Union[str, Path], key: str = "") -> list[str]:
    """清空会话授权（回到只剩 `--targets` 基线）；参考站名单一并清空。"""
    return write_scope(data_dir, [], key=key, reference=[])


#: 只读工具：**参考站名单只对这些工具生效**。判据是"读"，不是"能出网"——
#: 扫描/爆破/利用类工具永远只看 `targets`。
#: `chameleon_scrape_url` / `get_robots_txt` 是单页读取（前者带浏览器引擎，
#: 能过 WAF 的 JS 挑战）——站点级爬取（crawl_site / map_site）刻意不在名单里。
READ_ONLY_TOOLS: tuple[str, ...] = (
    "http_raw", "http_probe", "robots_fetch", "dns_lookup", "web_read",
    "chameleon_scrape_url", "chameleon_get_robots_txt",
)

#: 只读方法：带 method 的工具（http_raw）只认这两个（POST 等写动作不放行）
READ_ONLY_METHODS: tuple[str, ...] = ("GET", "HEAD")


def is_read_only_call(tool: str, args: Optional[dict] = None) -> bool:
    """参考站放行判据：工具在只读名单里，且（若带 method）是 GET/HEAD。"""
    if str(tool or "") not in READ_ONLY_TOOLS:
        return False
    method = str((args or {}).get("method") or "GET").strip().upper()
    return method in READ_ONLY_METHODS
