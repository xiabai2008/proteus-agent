"""XPentest 个人渗透 Agent：LLM 驱动的决策内核 + 工具注册表 + 自我进化。

- LLM 驱动：规划/决策/反思/技能提炼全部由大模型完成（非规则写死）
- 工具资产（rayscan/poxiao/ruoyi-scan 等）经 ToolRegistry 配置化接入，
  运行时校验存在性与版本，缺失即明确提示（本地可能滞后远程，以远程仓库为准）
- 规则只做三件事：安全护栏 / 输出解析 / 反幻觉校验
"""
from penagent.envcfg import load_env_file as _load_env_file

# 启动即装载 .env（键注入 os.environ，不覆盖已有）：
# 配置 JSON 里的 ${PENTEST_WS}/${PENTEST_TOOLS} 等占位符依赖这些键展开。
_load_env_file()

__version__ = "0.1.0"
