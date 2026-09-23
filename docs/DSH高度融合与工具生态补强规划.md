# DSH 高度融合与工具生态补强规划（2026-09-23）

> 两条工作流：**F（DSH 深度适配）** + **T（工具生态补强，上网找好项目）**。
> 铁律不变：不改 DSH 核心代码（只配置 + 插件）；所有 GitHub 拉取走 ghproxy 镜像
> （宿主直连 github.com 不通，docker/Dockerfile.sandbox 已有先例）。

---

## 〇、结论先行

- **F 项** 7 个（F1–F7），按"体感 × 成本"排序，先做 3 个：**进度流 + 两个命令插件**。
- **T 项** 3 档候选（T0 立即可落 / T1 评估后接 / T2 按需），全部为已核实存在的
  开源项目；接法优先"容器化 MCP server"（与 proteus-sandbox 镜像机制同构）。
- **前置改造**：接大工具面（HexStrike 150+ 工具）之前，内核必须先做
  **per-server 工具白名单**，否则工具清单炸上下文。

---

## 一、F 项：DSH 高度融合

现状基线（已实施）：preset 四层行（standard 全集 + persona + tools-policy + mcp-proteus）、
审计桥（spool → dsh-sync）、`tools/pre-execute` 裁决、审批三档、启动器/安装器/运行态检查。

| # | 项 | 现状痛点 | 目标形态 | 落点 | 量级 |
|---|---|---|---|---|---|
| F1 | **pentest_run 进度流** | 一次调用最长 600s 黑盒，CTF 里不知道它在干什么 | 内核 `mcp.py` 发 MCP `notifications/progress`（自研 JSON-RPC 已可扩展）；DSH mcp-client 原生显示 | 内核 mcp.py + 任务循环埋点 | 中 |
| F2 | **`/proteus-mode` 命令** | 模式只能靠模型在 pentest_run 参数里猜 | DSH command 插件（对照 `dsh-command-goal` 形状）+ 内核新增 `pentest_set_mode` MCP 工具（会话级默认模式） | 新 Cordis 插件行 + 内核工具 | 中 |
| F3 | **`/proteus-evidence` 命令** | 证据链/作战记录要切终端跑 CLI | command 插件调内核（`pentest_missions` 已有；补 `pentest_verify` 工具） | 新插件行 + 内核工具 | 小 |
| F4 | **技能融合** | 内核进化出的技能（成功率回写）会话侧看不见 | `python -m penagent skills --export` 导出为 DSH skills 目录，skill-filesystem 挂载；会话可直接引用 | 内核 CLI + preset 行 config | 小-中 |
| F5 | **审计可查** | spool 只在文件里，会话里查不了 | `/proteus-audit` 命令：最近事件 + dsh-sync 同步状态 | 新插件行 | 小 |
| F6 | **会话标题识别** | 会话列表分不清哪个在打靶 | 复用 session-title 机制，Proteus 会话标题带目标/模式 | 插件行 config | 小 |
| F7 | UI 面板（missions/evidence 可视化） | — | client 侧插件（DSH client-ui slot） | 后置 | 大 |

**形态原则**（沿用旁路治理文档结论）：机制与审计做插件（host/preset 行）；提供工具
继续走 MCP + 配置。command 插件就是"小插件"的标准形态——只注册命令、不做裁决。

---

## 二、T 项：工具生态补强（已核实的开源项目）

### 三种接入模式（按优先级）

1. **容器化 MCP server**：`docker run -i --rm <镜像>` 挂进 `penagent/mcp_servers.json`
   （stdio 传输，DSH 与内核两条链路同时受益）。与 R-15 的 proteus-sandbox 完全同构，
   Windows 上用 Docker Desktop 跑 Linux 工具。
2. **装进 proteus-sandbox 镜像**：给现有 CLI 工具链补二进制（Dockerfile 加层）。
3. **宿主直装**：仅 Windows 原生工具（尽量不用）。

### T0 — 立即可落（本周）

| 项目 | 事实 | 补什么空白 | 接法 |
|---|---|---|---|
| **mcp-security-hub**（ismailbozkurt/FuzzingLabs） | 24 个 Docker 化 MCP server、100+ 工具；非 root 容器 + Trivy 扫描；含 radare2-mcp(32 工具)/binwalk/yara/capa/searchsploit/ghidra/ida/hashcat/nmap/nuclei/sqlmap/ffuf… | **逆向、取证、二进制分析**（ghostpatch 暴露的最大空白） | 挑 3–5 个（radare2 / binwalk / yara / capa / searchsploit）up 后挂 mcp_servers.json |
| **CyberChef API MCP**（slouchd/cyberchef-api-mcp-server） | cyberchef-server 容器 + stdio 适配 | 编码链服务化（codec_chain 的百倍增强） | 容器 + mcp_servers.json |
| **proteus-sandbox 镜像扩层** | 现有 Dockerfile.sandbox（RsaCtfTool 已进） | **pwntools / checksec / binwalk / volatility3 / gdb**（CTF pwn 脚本基建） | Dockerfile 加层（ghproxy 拉取） |

### T1 — 评估后接

| 项目 | 事实 | 备注 |
|---|---|---|
| **HexStrike AI**（0x4m4/hexstrike-ai） | ~12k★ MIT；150+ 工具单 MCP 面（含 pwntools_exploit/angr/ropgadget/one_gadget/libc-database/volatility 等）；server+adapter 两段式；官方 Docker 支持 | **强大但工具面爆炸**——先做 §三 的 per-server 白名单再接；容器化跑（工具在容器里） |
| **radare2-mcp 官方版**（radareorg/radare2-mcp） | 官方维护、26+ 工具、stdio、支持 `-r` 只读与 minimode | 与 mcp-security-hub 版二选一（后者已打包） |
| **WireMCP**（tshark 流量分析 MCP） | 7 工具；Wireshark 系 | ghostpatch 类 pcap 活直接受益 |
| **Burp Suite MCP**（PortSwigger 官方） | 12 工具；被动为主 | 确认你的 Burp 版本支持再上（社区版受限） |

### T2 — 按需（题目驱动）

- **GhidraMCP**（LaurieWired，5.4k★）：反编译最强但 Java 重（headless 可自动化）
- **ida-pro-mcp**（mrexodia，12k★）：有 IDA Pro 许可证才值
- **pwn-mcp**（polarisxb，Node）：pwntools 模板 + 偏移计算，pwn 专项
- **semgrep-mcp**（semgrep 官方）：代码审计（对齐你的审计课件方向）
- **OSINT 三件套**：mcp-shodan / mcp-virustotal / mcp-dnstwist（需要 API key）

### 排重声明

本机已有：宿主 ~70 工具、R-15 镜像（nuclei/ffuf/gobuster/pocsuite3）、外部 MCP
（seckb 知识库 / RayScan / Chameleon）。**新项目只补空白**：逆向、pwn、取证、
编码链、流量分析。同类不重复接。

### 生态观察（同类项目，不集成，只做坐标）

PentAGI ~24.4k★、PentestGPT ~15.5k★、HexStrike ~12k★、IDA-Pro-MCP ~12k★——
"AI × 安全"赛道热度验证完毕；我们的差异化在**多模式机制性切换 + 证据链反幻觉 +
DSH 宿主融合**，不是工具数量。

---

## 三、支撑性内核改造（接大工具面的前提）

1. **per-server 工具白名单**：`mcp_servers.json` 增字段
   `tool_filter: {allow: [...], deny: [...]}`，装载时过滤——直接决定 HexStrike
   能不能接（150 工具全灌进注册表 = 上下文灾难）。
2. **镜像构建管线**：Dockerfile.sandbox 拆 build target（base / ctf / re），
   compose 编排多容器（sandbox + 工具 MCP 各容器）。
3. **工具去重器**：注册时检测"同名能力"（如 radare2 两个版），保留声明优先级高者。

---

## 四、建议落地顺序

1. **第 1 步**：T0 全落（镜像扩层 + 3–5 个容器 MCP + CyberChef）+ §三-1 filter 设计
2. **第 2 步**：F1（进度流）+ F2/F3（两个 command 插件）——"高度融合"体感最强的三件
3. **第 3 步**：HexStrike 容器化评估（有 filter 之后）+ T1 其余
4. **第 4 步**：F4/F5/F6；T2 按题目需要

每步的验收口径沿用现有传统：真机跑通 + 证据可复现 + 文档更新 + CI 绿。

---

## 五、风险与边界

- **GitHub 直连不通**：所有拉取走 ghproxy（`https://ghproxy.net/https://github.com`），
  钉 commit 保可复现（Dockerfile.sandbox 先例）。
- **Docker 依赖**：容器化 MCP 依赖 docker daemon；闪断时 `failOnStartupError: false`
  降级（少一组工具，不炸会话），但"没有工具就没有保护"——kernelGuard 已在管这条。
- **工具面安全红线**：新工具一律走 `mcp_servers.json` 声明 + 内核注册，危险工具
  照旧吃 PolicyGate / 沙箱档，不允许旁路。
- **DSH 版本耦合**：已机制化（2026-09-23）——`tools/dsh_compat_check.py` 把 7 个
  触面（包存在性 / persona API / tools-policy 钩子 / mcp-client schema / host
  补丁行 / CLI 入口 / 版本锁）做成可检测契约；`dsh/DSH_VERSION.lock` 锁定被验证
  的 harness commit；升级五步 SOP 在接入指南第九节。新增 F 项开发时遵守
  "耦合预算"原则：配置行 > MCP 工具 + 提示 > 插件 > 深钩子。

---

*本规划与 `docs/DSH插件化与内核旁路治理.md`（三步走已全部实施）衔接；
F 项是"第四步"——深度融合；T 项是"工具面打开"——不再局限于本机资产。*


---

## 六、执行记录（2026-09-23）

**T0-a 镜像扩层 ✅ 完成**（提交 `430633c`）
- `proteus-sandbox:latest` 加入：pwntools / checksec.py / volatility3 / binwalk /
  gdb / strace / ltrace / file / xxd；镜像 342MB → 877MB。
- 回归测试 `test_sandbox_image_ctf_toolkit`（走生产执行路径，2s 跑完）。
- 踩坑三条（都已写进 Dockerfile 注释）：① deb.debian.org 构建期拉不动 ——
  新增 `APT_MIRROR` 构建参数（本机用清华镜像）；② gobuster 3.8.x 移除了
  `version` 子命令，正确姿势 `gobuster --version`；③ pwntools / volatility3
  模块顶层都没有 `__version__`，自检改用 CLI（`pwn version` / `vol --help`）。

**§三-1 per-server tool_filter ✅ 完成**（同批提交）
- `mcp_servers.json` 条目新增 `tool_filter: {allow, deny}`；deny 优先、allow
  非空=仅放行列表内；discover 报告新增 `filtered` 计数（契约含错误路径）。
- 3 条新测试（allow 收窄 / deny 优先 / 无过滤不改变现状）。

**T0-b 容器化 MCP 🟡 部分完成**
- mcp-security-hub 已克隆调研（GHCR 无预构建镜像，需本地 build；README 中
  `FuzzingLabs/` 与仓库路径 `ismailbozkurt/` 不一致——以实际 clone 为准）。
- **radare2-mcp 受阻**：Kali WSL 侧环境已备齐（r2 6.0.5 + libradare2-dev +
  pkg-config + r2mcp 编译安装成功，含一行 `r_table_new` 适配补丁），但
  **r2mcp v1.8.8 的 `tools/list` 死锁**：initialize 4s 正常、ping 正常、
  tools/list 90s 零响应且进程存活无崩溃——上游缺陷，未接线（避免每次发现
  流程空等 120s）。
- 跟进选项：① 上游提 issue / 换版本；② 借 `r2mcp -T` CLI 能力自制薄 MCP 包装；
  ③ 改试 GhidraMCP。证据与探针分支已留在 `examples/mcp_e2e_probe.py`。
- CyberChef API MCP：未开始。

**F1 进度流 + F2/F3 命令插件 ✅ 完成（2026-09-23 第二轮）**
- F1：`PenAgent` 新增 `on_event` 回调（fail-open，异常不入任务语义），六个收口点
  统一走 `_finish` 发 `done` 事件；`PentestMCPServer` 把 mission_start / step /
  done 转成 MCP `notifications/progress`——**tools/call 带 `params._meta.progressToken`
  才发**（无令牌静默降级）。诚实备注：当前 DSH 版 mcp-client 尚未渲染 progress
  通知（上游能力），内核侧已按规范就绪，任意标准客户端（含后续 DSH 版本）可直接消费。
- F2：内核新增 `pentest_set_mode` MCP 工具 + 模式回落链 **调用参数 → 会话文件
  `data/session-mode.json` → `--default-mode`**；DSH 侧 `/proteus-mode [<id>]`
  命令（写同一份文件——内核逐次读取，**无需重启内核进程**；未知 id 结构化拒绝）。
- F3：内核新增 `pentest_evidence` MCP 工具 + `python -m penagent evidence` CLI
  （共享 `penagent/report.py` 一份实现）；DSH 侧 `/proteus-evidence [<id>]` 命令
  （spawn 短命 CLI，20s 超时；输出编码走 cli.py 既有 utf-8 兜底，真机验证无乱码）。
- 测试：mcp 侧 +5（进度令牌三态 / 模式回落优先级与损坏文件回落 / 证据摘要）、
  命令插件侧 +2（node 真加载插件调 handler，假仓库根 + 桩包全链路）；
  另把 drift 测试从硬编码计数改为按内容断言（对 preset 演进免疫）。
- preset 新增第三行 `proteus-commands`（专属行 3/4；全组合 4 行），已同步，
  roster `broken=no`；命令名/返回契约按 `dsh-commands` 现行 API（`rawInput` +
  `{kind,text}`），definitionId 可省。

**F1 进度流 + F2/F3 命令插件 ✅ 完成（2026-09-23 第二轮）**
- F1：`PenAgent` 新增 `on_event` 回调（fail-open，异常不入任务语义），六个收口点
  统一走 `_finish` 发 `done` 事件；`PentestMCPServer` 把 mission_start / step /
  done 转成 MCP `notifications/progress`——**tools/call 带 `params._meta.progressToken`
  才发**（无令牌静默降级）。诚实备注：当前 DSH 版 mcp-client 尚未渲染 progress
  通知（上游能力），内核侧已按规范就绪，任意标准客户端（含后续 DSH 版本）可直接消费。
- F2：内核新增 `pentest_set_mode` MCP 工具 + 模式回落链 **调用参数 → 会话文件
  `data/session-mode.json` → `--default-mode`**；DSH 侧 `/proteus-mode [<id>]`
  命令（写同一份文件——内核逐次读取，**无需重启内核进程**；未知 id 结构化拒绝）。
- F3：内核新增 `pentest_evidence` MCP 工具 + `python -m penagent evidence` CLI
  （共享 `penagent/report.py` 一份实现）；DSH 侧 `/proteus-evidence [<id>]` 命令
  （spawn 短命 CLI，20s 超时；输出编码走 cli.py 既有 utf-8 兜底，真机验证无乱码）。
- 测试：mcp 侧 +5（进度令牌三态 / 模式回落优先级与损坏文件回落 / 证据摘要）、
  命令插件侧 +2（node 真加载插件调 handler，假仓库根 + 桩包全链路）；
  另把 drift 测试从硬编码计数改为按内容断言（对 preset 演进免疫）。
- preset 新增第三行 `proteus-commands`（专属行 3/4；全组合 4 行），已同步，
  roster `broken=no`；命令名/返回契约按 `dsh-commands` 现行 API（`rawInput` +
  `{kind,text}`），definitionId 可省。

**T0 收尾 ✅（2026-09-23 傍晚）**
- **binwalk / searchsploit / capa** 三个容器化 MCP 本地构建并接线：
  `mcp_e2e_probe` 全绿（7 + 3 + 3 工具注册，真调用全部 ok=True；分析文件经
  `data/` 只读挂载到容器 `/samples`）。
- **CyberChef 栈落地**：`proteus-cyberchef-server` 常驻容器（宿主 127.0.0.1:3110，
  `--restart unless-stopped`）+ 适配器镜像 `proteus-cyberchef-mcp`（3 工具，
  bake 真调用通过；`hello → aGVsbG8=`）。
- **可复现性收口**：构建件纳管 `docker/mcp/`（补丁与来源逐条记录在 README）+
  `tools/build_mcp_images.py`（幂等；实测从纳管件复建四镜像全通过）。
- 构建补丁五条（全部实测原因）：apt 走清华；PyPI 走清华（直连 ReadTimeout）；
  GitHub 走 gh-proxy（binwalk 克隆 / capa release）；**`mcp` 钉 1.18.0**
  （2.x 删除 Server 装饰器 API，实测 2.2.0 直接 AttributeError）；cyberchef
  适配器自建 Dockerfile（官方 uv+ghcr 耦合深；钉版依赖 + `--no-deps` 绕开
  pip 解析冲突）。
- 未纳管（诚实记录）：yara-mcp（基础镜像当时不可达 + 优先级最低）；
  radare2-mcp（上游 tools/list 死锁，维持归档与三条跟进选项）。
