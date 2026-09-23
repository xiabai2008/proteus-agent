"""构建容器化 MCP 工具链镜像（docker/mcp 下的构建件）。

用法：
    python tools/build_mcp_images.py            # 全部四个顺序构建
    python tools/build_mcp_images.py binwalk    # 指定单个

日志落 data/_build_mcp_<name>.log。**幂等**：Docker 层缓存命中时秒完。
为什么不用上游 Dockerfile 直接构建、lib 里有哪些补丁，见 docker/mcp/README.md。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MCP_DIR = ROOT / "docker" / "mcp"
LOG_DIR = ROOT / "data"

# name → (构建上下文, 镜像 tag)
IMAGES = {
    "binwalk": (MCP_DIR / "binwalk", "proteus-mcp-binwalk:latest"),
    "searchsploit": (MCP_DIR / "searchsploit", "proteus-mcp-searchsploit:latest"),
    "capa": (MCP_DIR / "capa", "proteus-mcp-capa:latest"),
    "cyberchef": (MCP_DIR / "cyberchef-mcp", "proteus-mcp-cyberchef:latest"),
}


def build(name: str, ctx: Path, tag: str) -> bool:
    log = LOG_DIR / f"_build_mcp_{name}.log"
    print(f"[build] {name} → {tag}（日志 {log}）")
    with log.open("w", encoding="utf-8") as fh:
        proc = subprocess.run(
            ["docker", "build", "-t", tag, str(ctx)],
            stdout=fh, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-5:]
        print(f"[fail] {name}（exit={proc.returncode}）；日志尾部：")
        for line in tail:
            print("   ", line)
        return False
    print(f"[ok] {name}")
    return True


def main() -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    wanted = sys.argv[1:] or list(IMAGES)
    unknown = [w for w in wanted if w not in IMAGES]
    if unknown:
        print(f"未知镜像名 {unknown}；可选：{list(IMAGES)}")
        return 2
    failed = [n for n in wanted if not build(n, *IMAGES[n])]
    if failed:
        print(f"失败：{failed}")
        return 1
    print("全部完成。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
