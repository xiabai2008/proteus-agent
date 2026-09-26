# DSH 主体化交付说明（阶段 0/1/2）

> 面向：**未来接手的人**（含三个月后的自己）。
> 交付日期：2026-09-24　　范围：`P0-1..P0-6` + `P1-1..P1-5` + `P2-1..P2-4`（14 个提交）
> 相关文档：方案与执行记录 `docs/DSH主体化改造方案.md` · 待办编号 R-25..R-35
> `docs/修复待办清单.md` · 接入与排查 `docs/DSH宿主接入指南.md`
> **本文是入口**：先读本文，再按需跳到上面三份。

---

## 一、这次交付解决了什么（一句话版）

**把 Proteus 从"DSH 上的一个 MCP server"改造成"DSH 的三场景增强层"**：
打开 DSH、在选择器里选一个 Proteus 入口，该场景的**工具面、模式闸门、判定器、
记忆与技能分区、审批档位**一次性到位；会话内可用命令切模式与人工授权；
所有动作（含宿主 shell）都留痕、可机验、可出报告。

三个场景：**渗透**（`proteus-pentest`）/ **CTF Web**（`proteus-ctf-web`）/
**CTF Crypto**（`proteus-ctf-crypto`）。

---

## 二、快速上手（日常只用这三步）

```bash
# 1) 启动（渲染+同步三个 preset → 关旧实例 → 起 web profile）
<REPO>\dsh\start-proteus.cmd

# 2) 会话里选一个入口：Proteus 渗透 / Proteus CTF-Web / Proteus CTF-Crypto
#    （选择器里 order 5/6/7；UI 地址由启动器打印，带 token）

# 3) 会话内命令
/proteus-mode  ctf-crypto         # 切题型（工具面与宿主裁决档同时变）
/proteus-scope add <靶机>          # 人工授权目标（只有人能执行）
/proteus-evidence                 # 证据链校验 + 作战记录汇总
/proteus-tree [<mission-id>]      # 层级视图：任务 → 动作 → 产出
/proteus-skills                   # 导出经验库技能到本 preset 的技能目录
/proteus-audit                    # 审计通道快览（spool / 同步 / 链规模）
```

前置：环境变量 `PENTEST_WS` / `PENTEST_PY312` 已设置（`.env` 里有真实路径，
不入库）；Docker 桌面版**建议在跑**（容器化 MCP 与高危隔离执行依赖它）。

---

## 三、交付清单（按能力，不按提交顺序）

### 3.1 三个 preset（场景分流）

| | proteus-pentest | proteus-ctf-web | proteus-ctf-crypto |
|---|---|---|---|
| 默认模式 | `pentest-standard` | `ctf-web` | `ctf-crypto` |
| 工具面 | 52（含 nuclei/sqlmap/fscan + RayScan/Chameleon/seckb） | 34（CTF 六件套 + HTTP/侦察 + chameleon/seckb） | 19（CTF 六件套 + 文件分析 + seckb） |
| 明确不含 | CTF 工具 | nuclei/sqlmap/ffuf 等重型扫描器 | 同上 + chameleon |
| 判定器 | `evidence_chain` + `require_poc` | `flag_regex` | 同左 |
| 人格 | `prompts/dsh-persona.md` | `prompts/dsh-persona-ctf.md` | 同左 |
| 会话状态 | `session-*-pentest.json` | `session-*-ctf-web.json` | `session-*-ctf-crypto.json` |
| 技能目录 | `data/dsh-skills/pentest` | `data/dsh-skills/ctf-web` | `data/dsh-skills/ctf-crypto` |

> 工具数随外部依赖（Docker / RayScan / chameleon / seckb）变化；上表是
> 2026-09-24 真机实测值。**三个 preset 来自同一份模板渲染**——见 §五 维护须知。

### 3.2 内核侧（`penagent/`）

| 能力 | 交付物 | 关键行为 |
|---|---|---|
| 启动健壮性 | `mcp_client.py` EOF 哨兵 + stderr 尾巴 + `registry.discover_mcp(budget=)` | 外部 MCP 不可达时**快速失败**（实测 23 分钟 → 6.7s），失败原因带退出码与 stderr |
| 工具面裁剪 | `mcp.py::_mode_registry` / `_tools_schema` / `_maybe_notify_tools_changed` | **列表与执行同一判据**；模式变化发 `tools/list_changed`，DSH 自动重取 |
| 模式白名单 | `modes.py`（`fnmatch` 家族通配）+ `modes/ctf-*.yaml` | 名单写错即**测试失败**（`test_mode_tool_lists_reference_real_names`） |
| 会话授权 | `scope.py` + `mcp.py::_refresh_scope` | 人工命令写 `session-scope-<key>.json`；内核逐请求重读，**下一次调用即生效**；越界拒因带授权指引 |
| 会话态 HTTP | `http_session.py`：`session_http` / `replay_request` | cookie jar + `request_id` + 原样重放比对（状态码/正文哈希）；**凭据不回显**（请求头与 `Set-Cookie` 双脱敏） |
| 报告 | `report.py`：`report_gen`（markdown/**SARIF 2.1.0**）、`mission_tree`（三层视图）、`evidence_report` | 结论交付物 + 审计视图 |
| 评测分档 | `examples/eval_ctf_solve.py`（`milestones_for`/`grade_run`/`solve_graded`） | 33 题：`unguided` / `subtask`（里程碑比例）/ `subtask_guided`；判据落在**工具输出**上 |
| 去重 | `registry.register_spec` | 同名工具被不同来源覆盖时**记 note**（不静默） |

### 3.3 宿主侧（`dsh/`）

| 交付物 | 作用 |
|---|---|
| `_shared/agent.cordis.template.yml` | 三个 preset 的**唯一**组合来源（占位符渲染） |
| `_shared/proteus-tools-policy.mjs` | 目标动作裁决：越界 → `ask`（带授权指引）· **改写授权文件 → `deny`**（自我授权防线）· 内核缺位 → fail-closed · 按会话模式决定档位（CTF 放行范围内动作） |
| `_shared/proteus-supervisor.mjs` | 监督层：同工具同参数重复到阈值 → `deny`（理由含"换思路"提示）→ 再触发升级 `ask`；留痕 spool |
| `_shared/proteus-commands.mjs` | 六个命令（mode/scope/evidence/tree/skills/audit） |
| `proteus-bridge/` | host 平面 bundle：`session/event` → spool（全局事件，按 preset 打标） |
| `proteus.cordis.patch.yml` | 审批三档：`proteus-safe` / `proteus-standard` / `proteus-ctf` |
| `tools/dsh_install.py` | 渲染 + 同步 + 漂移校验 + roster 健康检查 + 旧目录迁移 |
| `tools/dsh_compat_check.py` | 对侧兼容性 7 项（DSH 升级前后必跑） |

---

## 四、怎么验证（三分钟自检）

```bash
# ① 本侧一致性：bundle 与 _shared/ 一致 / profile 已接线 / 补丁 / 审计桥 / 运行中 roster
python tools/dsh_install.py --check

# ② 对侧兼容性：DSH 里我们依赖的包与接口还在不在
python tools/dsh_compat_check.py

# ③ 全量测试（510 passed / 16 skipped；skip 全是容器类）
python -m pytest tests -q

# ④ 能力闸门：CTF 33 题离线跑（约 7 秒，含分档行）
python examples/benchmark.py --suite ctf
```

**真机会话三检查点**（2026-09-24 已按 preset 真实配置验过，UI 点击级见 §六）：

1. 工具面：`proteus-ctf-web` 会话里**没有** nuclei/sqlmap，但看得见
   `codec_decode` / `checksec_bin` / `http_raw`；
2. 授权：`http_raw` 打未授权目标 → `isError=true` 且拒因含 `/proteus-scope`；
   人执行 `/proteus-scope add <靶机>` 后**同一会话**再调即放行；
3. 监督：同一调用连点 5 次 → 第 5 次 `deny`、第 6 次 `ask`，spool 里有
   `kind=supervisor` 记录。

---

## 五、维护须知（**改之前必读**）

### 5.1 改 preset 的正确姿势（**2026-09-26 载具迁移后**）

preset 由仓库内 bundle `dsh/proteus-presets/` 承载，安装走 DSH 自己的工具。

- **改模板**：`dsh/.agent-presets/_shared/agent.cordis.template.yml`
- **改共享插件**：`dsh/.agent-presets/_shared/*.mjs`（唯一实现来源；**禁止**在
  preset 目录或 profile 目录里各放一份）。
- 改完**重渲染**：`python tools/render_preset_bundle.py`（把四个共享插件逐字节
  复制进 bundle、渲染声明行），再跑 `python tools/dsh_install.py --check`。
- **安装/更新**：`plugin_manager` → `action: install_bundle` → `target` 填
  `dsh/proteus-presets/` 的绝对路径。官方文档明确要求**不要用 shell 复现**
  包安装与 bundle 选择；profile patch 是热加载的（实测：改完选择器立刻生效）。
- **三条实测规则**见第九节——`./x.mjs` 相对行、目录发现废弃都属"写进去却不生效"
  那一类，改之前先读。
- 三个 preset 的差异**只允许**四类：默认模式 / 人格文件 / 会话键 / 显示名与排序。
  `tests/test_preset_bundle.py` 与 `test_shared_implementation_has_a_single_source`
  钉住这一点。

### 5.2 DSH 升级流程（顺序不能反）

```bash
python tools/dsh_install.py --check      # 0) 升级前基线
python tools/dsh_compat_check.py
# 1) 更新 DSH
python tools/dsh_compat_check.py         # 2) 升级后：FAIL 的每一项就是断点
# 3) 修 preset/插件 → 冒烟（§四 的 ①②④ + 真机会话）
# 4) 全绿后更新 dsh/DSH_VERSION.lock
```
细节见 `docs/DSH宿主接入指南.md` 第九节。**升级后优先复测深钩子**（`session/event`、
`tools/pre-execute`、`tools/list_changed`）。

### 5.3 这个项目最容易踩的坑（都是"静默失效"）

| 坑 | 症状 | 防线 |
|---|---|---|
| 文件写错名字（工具名/模式名） | **不报错**，只是永远不生效 | `test_mode_tool_lists_reference_real_names` |
| 安装副本漂移 | 改了代码没上线 | `dsh_install --check` 逐文件哈希 |
| 进程跑旧模块（Node ESM 缓存） | 会话行为不变 | `--check` 的运行态检查 + 重启 |
| 模板渲染漏占位符 | 行 config 变字面量 | `verify_preset` 检查未替换 token |
| 同名工具被覆盖 | 不知哪份在生效 | 注册中心记 note |
| 归属字段缺失 | 视图/审计退化（老数据） | 视图显式列出未归属记录，不丢 |

> 共同规律：**写进去就该生效的东西，判据要落在消费方视角**（agent 实际读到的
> 对象、链上真实的记录），并要求一次真机验证。

---

## 六、已知限制（诚实声明）

1. **UI 点击级验收未完成**（R-33）：桌面浏览器与 DSH 本地 HTTP 传输对
   "大响应 + chunked"不稳（`ERR_INCOMPLETE_CHUNKED_ENCODING`）。服务端侧正常
   （python/PowerShell 完整取到 39893 字节）。**绕过**：用系统浏览器打开启动器
   打印的 token URL。机制层已按 preset 真实配置验过（§四）。
2. **容器依赖**：`checksec_bin` / 容器化 MCP（binwalk/capa/yara/cyberchef/
   searchsploit/hexstrike）/ `python_solve` 都要求 Docker + 对应镜像；
   不可用时**拒绝执行**（fail-closed），不回落宿主直跑。
3. **裁决是启发式**：目标动作裁决按"网络动词 + 目标提取"判定（R-23），
   能做的是**提高旁路成本 + 留痕**，不是密不透风；只管 shell 工具。
4. **监督层阈值是缺省值**（同工具 5 次 / 会话 30 次）：prompt 密集但合法的
   排查可能被误拦——可按 preset 行配置调。内核侧另有一道独立判据（R-39，
   `REPEAT_FAILURE_LIMIT = 3`：同工具 + 同参数**连续失败**即拦，见
   `penagent/agent.py`），阈值同样写死、不进 ModeProfile；它**按任务重置**，
   所以**跨任务的循环仍只由宿主侧监督层兜住**（两道判据互补，不是同一份逻辑）。
5. **Jeopardy CTF 已饱和**（CAI/CSI 结论）：CTF 模式的定位是练手与真实比赛，
   不追刷分；能力投入优先给渗透与 A&D 方向。
6. **内层 ReAct 仍存在**（`pentest_run`）：按设计保留为"批处理执行器"，
   CTF preset 的工具面里**不含它**（决策权归外层）；渗透 preset 仍可用。
7. **P1-3 的"工具合并"没做**：`port_scan`/`naabu`/`fscan` 未合并——重命名会
   牵动白名单/文档/测试而收益有限；只做了同名覆盖留痕。
8. **`dsh-session` 回放套件的判分口径**（R-41）：只在"会话记录明确归属本次
   `--preset`（缺省 `proteus*`）+ 命中该靶入口之外的预期发现"时才判分；无该靶
   会话、归属未知、仅触达入口一律 `skipped`（不进分母）。老链（无 `preset`
   字段）默认不参与判分，要看不过滤口径须显式传空的 `--preset`。

---

## 七、变更历史（17 个提交）

| 提交 | 内容 |
|---|---|
| `5e54a33` | P0-1 启动健壮性（23 分钟 → 6.7s） |
| `d81f3d7` | P0-2 CTF allow 修真名 + 家族通配 |
| `bf95551` | P0-3 工具面按模式裁剪 + `listChanged` |
| `3d88aba` | P0-4 会话授权入口 + 自我授权防线 |
| `f2e82f8` | P0-5 模式贯通宿主裁决 |
| `96563f8` | P0-6 三个 preset 场景分流 + 旧目录迁移 |
| `75549ee` | 文档同步（AGENTS.md / 接入指南） |
| `2295de0` | P1-1/4/5 渗透三件套 + 阶段流水线 + 技能双套（并修掉 `Set-Cookie` 凭据回吐） |
| `3bf8aa1` | P1-2/3 + P2-1/4 checksec · 去重器 · 监督层 · 注入护栏 |
| `75c8851` | 文档收口（执行记录） |
| `c149109` | 兼容检查跟上新布局 |
| `2710a61` | 真机冒烟记录（三检查点 + UI 阻塞证据） |
| `782a792` | P2-2 评测分档 |
| d244756 | P2-3 审计层级视图（并修掉作战记录分区盲区） |
| 898c1fe | 实测轮修复：工具业务失败统一判 `ok=False`（外层模型终于有纠正信号）+ `reflect` / `pentest_reflect` 跨分区定位（技能沉淀闭环打通） |
| 68d44a0 | 实测轮修复：CTF 工具面路径口径统一（`/samples` ↔ data 目录，含失败信息可操作化）+ 补上 `checksec_bin` 承诺却从未挂载的容器挂载（R-38 / R-43） |
| 22fd6cd | R-42 其余小项：supervisor 删死代码 · CLI 行缓冲 · suggest 同分定序 · tree 注明 flag 引用 |
| 80b39fa | R-39 内核侧补重复失败检测：同工具 + 同参数连续失败到阈值即拦并回灌纠正指令 |
| 0c601b6 | R-40 LLM 输出不可解析不再废掉整轮：分出 `LLMOutputError`，回灌纠正提示重试 3 次且不记步数 |
| daebb06 | R-41 `dsh-session` 回放判分加门槛：无匹配会话 / 证据不足记 `skipped` 而非 `failed`，`--preset` 支持 fnmatch 家族通配（待修清零） |
| `8636da6` | 载具迁移：preset 改由仓库内 bundle `dsh/proteus-presets/` 承载（桌面端 0.1.7 已移除目录发现），三条解析规则实测；`dsh_install.py` 改为渲染 + 读运行态 roster；7 个脚本去掉本机路径 |

**测试基线**：450 → **564 passed / 0 failed / 1 skipped**（每个提交都带回归用例；那 1 条
skip 是等 DVWA 的 CSRF token，lab 标记用例的端口误判已由 R-42 的 `identifies()`
判据修掉）；
待办编号：**R-25..R-44**——**全部收口（R-41 于 2026-09-25 修完，待修清零）**；
2026-09-24 实测轮的 R-39（内核侧重复失败检测：同工具 + 同参数连续失败到阈值即拦
并回灌"上次失败原因 + 换思路"）、R-40（LLM 输出不可解析不再废掉整轮：`LLMOutputError`
分出"形态失误"与"调用失败"，前者回灌"只输出一个 JSON 对象"提示重试 3 次且不记步数）、
R-41（`dsh-session` 无匹配会话/证据不足记 FAIL → 提取宽 / 判分严两层口径，一律 `skipped`；
`--preset` 改 fnmatch 家族通配、缺省 `proteus*`）
与 R-42（靶场身份判据 + 三个附带小项）已修（逐条见
`docs/修复待办清单.md` 第四节之二）。

---

## 八、文档地图

| 想知道什么 | 看哪份 |
|---|---|
| **交付了什么、怎么维护**（本文） | `docs/DSH主体化交付说明.md` |
| 为什么这么设计、每步的实测证据 | `docs/DSH主体化改造方案.md` |
| 怎么装、怎么排查、DSH 升级 SOP | `docs/DSH宿主接入指南.md` |
| 某条问题的定位与修法（R-* 编号） | `docs/修复待办清单.md` |
| 宿主旁路治理的三层分工与实测 | `docs/DSH插件化与内核旁路治理.md` |
| 开源对标（PentAGI / Strix / Cybench / CAI） | `docs/DSH主体化改造方案.md` 第三节 |
| 能力评测怎么跑、分数怎么读 | `docs/评测骨架.md` |
| 内核自身的说明 | `docs/XPentest内核README.md` |

---

## 九、桌面端 preset 载体迁移（2026-09-26，真机实测）

### 9.1 起因：旧载具被上游删掉了

官方桌面端 **0.1.7-rc.2**（nightly，profile = `desktop`）起，安装版随附文档
（app.asar 内 "Editing Cordis compositions"）原文：

> Agent presets are ordinary `@deepseek-ai/dsh-agent-preset` declarations carried
> by bundle patches. **Nothing edits a declaration in place**: a preset is created
> or changed by installing a bundle whose patch declares or overrides it.
> … Before declaration rows, a user preset was a directory
> `$DSH_HOME/.agent-presets/<id>/` … **Nothing reads that directory any more.**

字节级核对（`app.asar` 原始扫描）：`discoverPresets` **0 命中**、
`includeUserRoot` **0 命中**、`$DSH_HOME/.agent-presets` 只剩那句迁移说明。
也就是说仓库原先的"复制到 `~/.dsh/.agent-presets/` + 启动前同步 + 漂移校验"
在桌面端**已经无效**，而当时的 `tools/dsh_install.py --check` 仍报"接入健康"
（它走的是 `~/.dsh/profiles/node_modules` 里 0.1.6-alpha.2 的旧 API）——
**校验器与消费方脱节**，真机选择器里只剩一个手写迁移过去的 `proteus-ctf-web`。

### 9.2 三条实测规则（探针对照实验，**改 preset 前必读**）

装了三个一次性探针 bundle（装完即卸），六个对照 preset：

| 插件行写法 | 结果 |
|---|---|
| `@deepseek-ai/dsh-persona`（裸包名） | 可解析 |
| `./probe-persona.mjs`（文件**只在 bundle 里**） | **broken：`never started`** |
| `./profile-only-probe.mjs`（文件**只在 profile 目录**） | 可解析 |
| `@local/dsh-proteus-probe2/persona`（包自引用子路径） | **可解析** |

结论：

1. bundle 补丁里插入声明行 → 生效；裸包名可解析；
2. **`./x.mjs` 相对行的解析基准是 profile 目录，不是 bundle 目录**——写在
   bundle 里必然 broken（`broken` 的 preset **不进选择器、界面零提示**）；
3. **包自引用子路径**可解析 → 插件本体留在 bundle 内，profile 目录不需要副本；
4. 失败的 preset 会在 roster 上留 `broken: "<行id> (<name>): never started"`，
   这是唯一的可见信号——所以校验必须读**运行中 DSH 的 roster**。

### 9.3 现在的形态

```
dsh/proteus-presets/                 # 新载具（仓库内、可 review、可回滚）
  package.json                       # dsh.bundle.patch + exports（四个插件子路径）
  cordis.patch.yml                   # 三个声明行 preset-proteus-{pentest,ctf-web,ctf-crypto}
                                     #   + host 平面审计行 proteus-bridge（role: audit）
  proteus-{persona,tools-policy,supervisor,commands}.mjs   # _shared/ 的逐字节副本
```

- 生成器：`tools/render_preset_bundle.py`（幂等，`--check` 只校验）；
- 安装：`plugin_manager` → `install_bundle` → `target` = 该目录绝对路径
  （本机装在 `desktop` profile：profile 的 `package.json` 记 `link:` 依赖 +
  `dsh.profile.bundles` 列表，并建 `node_modules/<包名>` junction）；
- 校验：`python tools/dsh_install.py --check` —— 查 bundle 与来源一致、
  声明行齐全、无 `./` 相对行、profile 已登记、**运行中 DSH roster** 三个都在且
  未 broken（`--roster-port`，缺省依次试 19387/4080；不可达时跳过并注明）；
- 迁移时清掉的东西：profile patch 里三段重复的手写声明 + 审计行（974 → 216 行）、
  profile 目录里 4 份 `.mjs` 副本、`~/.dsh/.agent-presets/proteus-*` 三个旧目录
  （已移到 `$DSH_HOME/backups/proteus-legacy-preset-dirs-20260926/`）；
  `tools/migrate_preset_to_declaration.py` 已删除（迁移完成后留着只会在 profile
  patch 里重新注入一份手写声明）。

> 新增一个**场景入口**的代价：`modes/<id>.yaml` + 渲染器 `PRESETS` 加一项 +
> `dsh/.agent-presets/<id>/preset.yml`（显示名/描述/排序）+ 重渲染 + `install_bundle`
> 一次。内核侧只想换作战场景时**不必**新增入口——用 `/proteus-mode` 切换即可
> （项目反目标：度量未建立前不加新模式，见 `docs/能力加强路线.md`）。
