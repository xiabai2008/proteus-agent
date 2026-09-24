# 容器化 MCP 工具链（docker/mcp）

T0（规划：DSH高度融合与工具生态补强）落地的四个容器化 MCP server。
**这里保存的是打过补丁的构建件**（上游 clone 在 data/repos 不入库，不可复现），
补丁原因逐条记录在下方与各 Dockerfile 注释里。

## 镜像清单

| 目录 | 镜像 | 工具 | 传输 | 备注 |
|---|---|---|---|---|
| `binwalk/` | `proteus-mcp-binwalk:latest` | 7（scan/extract/entropy/hexdump…） | stdio | 分析文件经 `data/` 只读挂载到 `/samples` |
| `searchsploit/` | `proteus-mcp-searchsploit:latest` | 3（search/examine/recent） | stdio | 无需挂载 |
| `capa/` | `proteus-mcp-capa:latest` | 3（analyze/…） | stdio | 同 binwalk 挂载 |
| `cyberchef-mcp/` | `proteus-mcp-cyberchef:latest` | 3（bake/batch_bake/magic） | stdio | 依赖 `proteus-cyberchef-server` 容器（见下） |
| `hexstrike/` | `proteus-hexstrike:latest` | 上游 151 → **allow-list 6** | stdio（适配器） | 依赖 `proteus-hexstrike-server` 容器（见下） |
| `yara/` | `proteus-mcp-yara:latest` | 5（scan/scan_with_rules/list_rulesets/…） | stdio | 内置 malware/crypto/packers/cve 规则集；样本经 `/samples` 只读挂载 |

上游来源（均 MIT/Apache）：
- 前三者：`ismailbozkurt/mcp-security-hub`（FuzzingLabs 维护；README 里的
  `FuzzingLabs/` 路径与仓库不一致，以实际 clone 为准）；
- `cyberchef-mcp`：`slouchd/cyberchef-api-mcp-server`；
- Chef 服务端：`gchq/CyberChef-server`（容器 `proteus-cyberchef-server`）；
- `hexstrike/`：`0x4m4/hexstrike-ai` v6.0（server + MCP 适配器两文件纳管）。
- `yara/`：`ismailbozkurt/mcp-security-hub` 的 binary-analysis/yara-mcp（同前三者）。

## 本地补丁（为什么不是直接上游构建）

1. **apt 换清华镜像**：构建期 deb.debian.org 拉不动（实测超时）。
2. **PyPI 换清华镜像**：构建期 files.pythonhosted.org 读超时（实测 ReadTimeout）。
3. **GitHub 走 gh-proxy**：host 直连 github.com 不通——binwalk 源码克隆、
   capa release 下载均改 `https://gh-proxy.com/`。
4. **钉 `mcp==1.18.0`**：这些 server 用 `Server.list_tools()/call_tool()` 装饰器，
   mcp 2.x 已删除该 API（实测 2.2.0 直接 AttributeError）；requirements 原为
   `mcp>=1.0.0` 会漂到 2.x，故钉死。
5. **cyberchef-mcp 自建 Dockerfile**：官方用 uv + ghcr base + BuildKit bind
   mount，本地耦合深；改为 python:3.12-slim + 钉版依赖 + `--no-deps` 装本体
   （pyproject 的 `mcp>=1.6.0` 过松，pip 全新解析会 ResolutionImpossible）。
6. **hexstrike 收窄三件**：① 工具集只装基线 6 件（nikto 实测不在 bookworm 源，
   E: Unable to locate package；云工具/msf/wpscan 依赖过重按需再扩）；
   ② 去掉 angr/pwntools（实测只出现在生成的模板字符串里，非运行时依赖）、
   把上游写错的 `fastmcp` 依赖修正为 `mcp==1.18.0`（代码实际
   `from mcp.server.fastmcp import FastMCP`）；③ **tool_filter allow-list 6 个**
   ——上游 151 工具里混有 `create_file/delete_file/execute_python_script/
   install_python_package/execute_command` 等任意执行面，必须收紧后才准接入
   （allow：nmap_scan / nmap_advanced_scan / dirb_scan / hydra_attack /
   john_crack / hashcat_crack；密码攻击三件套是本仓当前缺口）。
7. **yara 三补丁**：apk 走清华（dl-cdn 直连不稳）、规则克隆走 gh-proxy、
   pip 钉 `mcp==1.18.0`（同全仓策略）。

## 构建

```bash
python tools/build_mcp_images.py            # 四个镜像顺序构建（日志落 data/_build_mcp_*.log）
python tools/build_mcp_images.py binwalk    # 只构建指定镜像
```

## 运行

- binwalk / searchsploit / capa / cyberchef **适配器** / hexstrike **适配器**：
  无需常驻——内核 `mcp_servers.json` 每次调用 `docker run -i --rm`（见各条目
  `command`）。
- **CyberChef Server 必须常驻**（适配器只是代理）：

```bash
docker build -t proteus-cyberchef-server:latest .   # 本目录外：上游 clone 的 cyberchef-server/
docker run -d --name proteus-cyberchef --restart unless-stopped \
  -p 127.0.0.1:3110:3000 proteus-cyberchef-server:latest
curl -s -X POST http://127.0.0.1:3110/bake \
  -H 'Content-Type: application/json' \
  -d '{"input":"hello","recipe":[{"op":"To Base64","args":[]}]}'   # → {"value":"aGVsbG8="}
```

- **HexStrike Server 必须常驻**（工具在 server 侧执行；适配器只做 HTTP 转发）：

```bash
python tools/build_mcp_images.py hexstrike          # 构建 proteus-hexstrike:latest
docker run -d --name proteus-hexstrike-server --restart unless-stopped \
  -p 127.0.0.1:8888:8888 proteus-hexstrike:latest
curl -s http://127.0.0.1:8888/health                # 健康检查
```

（`proteus-cyberchef-server` 的构建件不在本目录——上游 Dockerfile 无需补丁；
构建命令见上述第一行，上下文为 `data/repos/cyberchef-server/`。）

## 联调自检

```bash
python examples/mcp_e2e_probe.py binwalk        # 扫描 data/ctf/ghostpatch/fw_v2.bin
python examples/mcp_e2e_probe.py searchsploit   # 检索 "apache 2.4"
python examples/mcp_e2e_probe.py capa           # 分析同一 ELF
python examples/mcp_e2e_probe.py cyberchef      # hello → To Base64（需 chef-server 在跑）
python examples/mcp_e2e_probe.py hexstrike      # nmap -sT 扫宿主 3110/4080（需 hexstrike-server 在跑）
python examples/mcp_e2e_probe.py yara           # 内置规则集扫 fw_v2.bin
```

## 未纳管（诚实记录）

- **radare2-mcp**：r2mcp v1.8.8 的 `tools/list` 死锁（上游缺陷）。2026-09-24
  尝试非 ASAN 重编验证「ASAN 导致死锁」假设：Makefile 把 r2 库列表塞在
  LDFLAGS、ASAN 注入在 configure 生成的默认 CFLAGS，两次覆盖式重编分别
  死于丢头文件/丢库——**验证成本超阈值，归档**。后续路径：上游 issue /
  换 GhidraMCP。证据见 probe_radare2 注释。
- **HexStrike 其余能力**（明确收窄，非遗漏）：nikto（bookworm 无包）、
  wpscan（Ruby 依赖重）、metasploit（体积 GB 级）、浏览器 agent（需 Chrome）、
  云工具（需云凭据）、`create_file/execute_command/install_python_package`
  等任意执行面（**永久拒绝**，见补丁 6）。
