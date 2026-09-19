"""核对新 agent.cordis.yml 引用的全部 @deepseek-ai 包在本机 harness 是否存在。"""
from pathlib import Path
import re

NM = Path(r"C:\Users\HZR\.dsh\profiles\node_modules\@deepseek-ai")
yml = Path(r"D:\HZR_PROJECTS\proteus-agent\dsh\.agent-presets\proteus\agent.cordis.yml"
           ).read_text(encoding="utf-8")
pkgs = sorted(set(re.findall(r"@deepseek-ai/([a-z0-9-]+)", yml)))
missing = [p for p in pkgs if not (NM / p).is_dir()]
for p in pkgs:
    mark = "OK " if (NM / p).is_dir() else "缺失"
    print(f"{mark} {p}")
print("缺失数:", len(missing))
