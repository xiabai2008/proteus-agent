"""核对 agent.cordis.yml 引用的全部 @deepseek-ai 包在本机 harness 是否存在。

本机路径从运行时解析，不写死在源码里（硬规则 7）：
- 包目录：`DSH_NODE_MODULES` 环境变量，缺省 `<主目录>/.dsh/profiles/node_modules/@deepseek-ai`
- preset：命令行第一个参数，缺省本仓库的 `dsh/.agent-presets/proteus/agent.cordis.yml`
"""
from pathlib import Path
import os
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
NM = Path(os.environ.get("DSH_NODE_MODULES")
          or Path.home() / ".dsh" / "profiles" / "node_modules"
          / "@deepseek-ai")
yml = (Path(sys.argv[1]) if len(sys.argv) > 1
       else ROOT / "dsh" / ".agent-presets" / "proteus" / "agent.cordis.yml"
       ).read_text(encoding="utf-8")
pkgs = sorted(set(re.findall(r"@deepseek-ai/([a-z0-9-]+)", yml)))
missing = [p for p in pkgs if not (NM / p).is_dir()]
print(f"包目录: {NM}")
for p in pkgs:
    mark = "OK " if (NM / p).is_dir() else "缺失"
    print(f"{mark} {p}")
print("缺失数:", len(missing))
