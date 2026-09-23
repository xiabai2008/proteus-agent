# HexStrike AI v6.0 精简容器（2026-09-23，T0 第 3 步评估落地）。
#
# 上游：0x4m4/hexstrike-ai（MIT）——server（Flask REST :8888，工具在宿主机
# subprocess 执行）+ mcp 适配器（stdio，HTTP 转发）。
#
# 与上游完整形态的差异（全部为「评估后有意收窄」，见 docker/mcp/README.md）：
#   1. 不装 150+ 工具全集（大量重复本仓已有能力）：只装 6 个基线工具
#      ——nmap / dirb / sqlmap / hydra / john / hashcat（nikto 不在 bookworm 源，实测确认）
#      （密码攻击三件套是本仓当前缺口；其余为基线覆盖）。
#   2. 不装 angr / pwntools：实测只为「生成模板字符串」，非运行时依赖。
#   3. 不装 wpscan / metasploit / 云工具 / 浏览器 agent：体积与依赖过重，
#      按需再扩（上游内核代码留全，装齐即可用）。
#   4. 适配器依赖换 `mcp==1.18.0`：上游 requirements 写的 fastmcp 包与实际
#      代码 `from mcp.server.fastmcp import FastMCP` 不符（2026-09-23 实测）。
#
# 镜像同时含 server 与适配器：常驻 server（工具执行方），按需 `docker run -i`
# 拉起适配器（只做 HTTP 转发）。
FROM python:3.12-slim

# apt / pip 走国内镜像（构建期直连实测超时，与 docker/mcp 其他镜像同策略）
RUN sed -ri "s|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g" /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap dirb sqlmap hydra john hashcat ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.hexstrike.txt ./
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple \
      -r requirements.hexstrike.txt

COPY hexstrike_server.py hexstrike_mcp.py ./

# 构建期自检：依赖导入 + 两个入口可加载（--help 会完整跑一遍 import 链）
# + 关键工具在位。任一失败 = 构建失败，不留半残镜像。
RUN python -c "import flask, psutil, aiohttp, bs4, selenium, mitmproxy; print('deps ok')" \
 && python hexstrike_server.py --help >/dev/null 2>&1 \
 && python hexstrike_mcp.py --help >/dev/null 2>&1 \
 && nmap --version | head -1 \
 && dirb 2>&1 | head -1 \
 && (john --list=build-info 2>/dev/null | head -1 || john 2>&1 | head -1) \
 && hashcat --version

EXPOSE 8888
CMD ["python", "hexstrike_server.py"]
