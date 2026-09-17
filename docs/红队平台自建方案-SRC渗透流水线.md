# RedForge 自建方案 — 面向 SRC 众测的 Web 渗透流水线

版本 v0.1 | 场景：Web 渗透 / SRC 众测 | 核心痛点：工具串联与自动化 | 前提：自建、源码可控、可随时升级

---

## 0. 需求重定义

你给的两个约束，把产品形态彻底改变了：

| 你的输入 | 推导出的结论 |
|---------|-------------|
| 场景 = Web 渗透 / SRC 众测 | 目标是**一批**，不是**一个**。批量、快速、广度为王，单目标深度利用不重要 |
| 痛点 = 工具串联与自动化 | 核心价值在**编排**，不在**推理**。你要的是流水线，不是自主 Agent |
| 要求 = 自建、源码可调 | 但自建不等于全自己写。**差异化层自研，通用层复用** |

**结论：你要的不是"红队平台"，是一个 Web 渗透流水线引擎，外加 AI 辅助判断。**

这不是降级，是聚焦。理由：

- SRC 的真实工作流是「一批目标 → 前期自动化跑完 → 人工只做最后的验证和提交」。中间的自动化就是全部痛点所在。
- 平台级产品（工具接入 × 阶段编排 × Web UI × 权限 × 审计）以你当前时间，6 个月起步且未必可用。流水线引擎 **1~2 周就能出第一个真能用的版本**。
- AI 在这个场景里是加分项，不是地基。先有流水线，AI 才有东西可辅助。

---

## 1. 产品形态

**双形态，一个内核：**

```
形态一（P0，先用起来）：CLI 流水线引擎
    redforge run -i targets.txt --pipeline web-basic

形态二（P2，再加壳）：dsh 插件
    对 dsh 说"把这批域名跑一遍前期侦察和扫描，把确认的问题整理出来"
```

**内核是同一个流水线引擎。dsh 只是它的一个调用方。**

- **流水线引擎** = 手脚：执行、调度、断点续跑、去重、落库
- **dsh** = 大脑：选择策略、研判结果、撰写材料

这个分层的关键在于：**手脚不依赖大脑也能跑**。dsh 挂了，CLI 照常能用。反过来不成立。所以先做手脚。

---

## 2. 架构

```
输入：目标列表（txt / 一行一个域名）
  │
  ├─ S1 资产发现      subfinder · asset-survey（聚合 FOFA/Hunter/Quake）
  ├─ S2 存活与指纹    httpx · RayScan 指纹库
  ├─ S3 漏洞发现      Nuclei · poxiao · ruoyi-scan（并行）
  ├─ S4 三态判定      验证引擎 · 证据固化
  └─ S5 产出交付      去重清单 · SRC 提交材料
       │
       └─ 状态层：SQLite（每个阶段结果落库，断点续跑）
```

**关键：每一阶段的输出都落库，下一阶段从库里读，不靠内存传递。**这是断点续跑和增量重跑的前提，也是整个引擎设计的地基。

---

## 3. 数据模型（SQLite）

六张表就够了。这套模型参考了 `howmp/dsh-pentest` 的六表设计思路（只借鉴思想，不抄代码——它没有开源许可证）。

```sql
-- 目标
CREATE TABLE targets (
    id          INTEGER PRIMARY KEY,
    value       TEXT NOT NULL UNIQUE,   -- 域名或 URL
    kind        TEXT,                   -- domain | url
    parent_id   INTEGER,                -- 子域指向根域
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 任务：某目标在某阶段的某次执行
CREATE TABLE tasks (
    id          INTEGER PRIMARY KEY,
    target_id   INTEGER NOT NULL,
    stage       TEXT NOT NULL,          -- asset | probe | scan | verify | report
    tool        TEXT NOT NULL,
    params_hash TEXT NOT NULL,          -- 参数指纹，用于幂等复用
    status      TEXT NOT NULL,          -- pending|running|done|failed|skipped
    started_at  TIMESTAMP,
    ended_at    TIMESTAMP,
    error       TEXT,
    UNIQUE(target_id, stage, tool, params_hash)   -- 断点续跑的核心约束
);

-- 发现（候选漏洞）
CREATE TABLE findings (
    id          INTEGER PRIMARY KEY,
    target_id   INTEGER NOT NULL,
    vuln_type   TEXT NOT NULL,
    severity    TEXT,
    title       TEXT,
    url         TEXT,
    fingerprint TEXT NOT NULL,          -- 去重指纹
    state       TEXT NOT NULL,          -- CONFIRMED | SAFE | UNKNOWN
    confidence  REAL,
    sources     TEXT,                   -- JSON 数组：哪些工具发现了它
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fingerprint)
);

-- 证据
CREATE TABLE evidence (
    id          INTEGER PRIMARY KEY,
    finding_id  INTEGER,
    task_id     INTEGER NOT NULL,
    kind        TEXT NOT NULL,          -- request|response|screenshot|dnslog|file
    content     TEXT,                   -- 原文或对象存储路径
    sha256      TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 流水线运行记录
CREATE TABLE runs (
    id          INTEGER PRIMARY KEY,
    pipeline    TEXT NOT NULL,
    input_file  TEXT,
    started_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at    TIMESTAMP,
    status      TEXT
);

-- 目标级熔断（WAF/限速保护）
CREATE TABLE target_health (
    target_id   INTEGER PRIMARY KEY,
    waf_detected BOOLEAN DEFAULT 0,
    error_count  INTEGER DEFAULT 0,
    last_status  TEXT
);
```

**三个设计要点：**

1. **`tasks` 表的唯一约束 `(target_id, stage, tool, params_hash)` 是断点续跑的全部秘密。**重跑时先查这个 key，状态为 `done` 就直接复用结果，不重复执行。
2. **`findings.sources` 是 JSON 数组。**同一个漏洞被 Nuclei、poxiao、ruoyi-scan 都发现时，合并成一条记录，三个来源都记上。**这解决 SRC 场景最烦的事：同一漏洞被重复报告。**
3. **`findings.state` 是三态枚举，不是布尔值。**这是你区别于所有同类工具的地方，后面单独讲。

---

## 4. 流水线定义（YAML 声明式）

**这是满足你"随时调整升级"诉求的关键设计——改流程不用改代码。**

```yaml
name: web-basic
description: SRC 前期自动化：子域 → 存活 → 指纹 → 扫描 → 报告

stages:
  - id: asset
    tool: subfinder
    inputs:
      - "$.targets[].value"
    outputs: subdomains
    parallel: 8

  - id: probe
    tool: httpx
    inputs:
      - "$.asset.subdomains"
    outputs: alive_hosts
    filter: "status_code < 400 && content_length > 0"
    parallel: 20
    rate_limit: 50/s

  - id: scan
    tool: nuclei
    inputs:
      - "$.probe.alive_hosts[].url"
    args:
      severity: "medium,high,critical"
      templates: auto          # 依指纹自动选模板
    outputs: candidates
    parallel: 5
    rate_limit: 10/s

  - id: scan_ruoyi
    tool: ruoyi-scan
    inputs:
      - "$.probe.alive_hosts[].url"
    when: "fingerprint contains 'ruoyi'"    # 条件执行
    outputs: candidates

  - id: report
    tool: markdown_report
    inputs:
      - "$.findings[state=CONFIRMED]"
      - "$.findings[state=UNKNOWN]"
    outputs: report.md
```

几个要点：

- **`when` 条件执行**：只在指纹匹配时才跑 ruoyi-scan。避免无脑全量扫，降低噪声和耗时。
- **`rate_limit` 和 `parallel` 是每阶段独立配置的**。SRC 场景最怕把目标打挂或触发封 IP，这个必须精细可控。
- **`outputs` 命名后，后续阶段用 `$.stage_id.outputs` 引用**。阶段解耦，改一处不影响其他。

---

## 5. 节点契约（工具适配层）

每个工具封装成一个 Node，统一接口：

```python
# nodes/base.py
from dataclasses import dataclass

@dataclass
class NodeResult:
    records: list[dict]        # 结构化记录，直接入库
    evidence: list[dict]       # 证据（请求/响应等）
    error: str | None = None

class Node:
    name: str                  # 节点名
    tool: str                  # 实际调用的工具
    side_effects: str          # read | write | destructive

    def run(self, ctx: "RunContext", inputs: list) -> NodeResult:
        raise NotImplementedError
```

**验收标准（重要）：一个 Node 只有满足这些才算合格**

1. 输出是**结构化**的（JSON/JSONL 优先），不是需要正则抠的彩色文本
2. 声明了 `side_effects`
3. 支持 `--dry-run`（只打印要执行的命令，不真跑）
4. 超时可控，超时后能被干净地杀掉

**不合格的不要接。**接入一个需要写复杂解析器的工具，维护成本会超过它带来的价值。

---

## 6. 三态判定（你的核心差异化）

这是整个方案里唯一"别人没有"的部分，值得单独设计。

### 6.1 判定规则

| 状态 | 判定条件 | 用途 |
|------|---------|------|
| **CONFIRMED** | 有完整证据：重放请求得到预期响应 / OAST 收到回连 / 差异比对确认 | 可直接提交 SRC，可直接利用 |
| **SAFE** | 已主动验证且确认不存在：补丁已打、参数已过滤、路径不可达 | **记录"已验证不存在"，避免重复扫描** |
| **UNKNOWN** | 无法验证：WAF 拦截、目标超时、需要认证、超出速率限制 | **必须单独列出，交人工跟进** |

### 6.2 为什么 SAFE 和 UNKNOWN 都要留

- **SAFE 不是"没结果"，是有价值的情报。**下一轮扫描、下一个目标，都可以据此跳过。竞品的 finding 都是单向的（只记证实的漏洞），这一维度全部缺失。
- **UNKNOWN 是 AI 时代的刚需。**大模型天然倾向"给一个结论"而不是"承认不知道"。把 UNKNOWN 做成一等状态，是**对抗幻觉的机制设计**，不是分类标签。

### 6.3 SRC 场景的实际价值

你现在拿到的扫描结果，大概率是一坨混在一起的"疑似漏洞"。三态判定把这一坨拆成三堆：

```
CONFIRMED  → 直接整理提交（省下最耗时的甄别工作）
SAFE       → 归档，下轮不再扫（省时间）
UNKNOWN    → 人工重点跟进（这才是真正需要你的判断力的地方）
```

**这才是你"自己构建"的真正理由**——不是别人做不到流水线，是别人不会给你这个三态视图。

---

## 7. AI 放在哪（可选，别当必需）

dsh 在这个方案里有三个位置，**都建立在流水线已经能跑的前提上**：

| 位置 | 做什么 | 价值 |
|------|-------|------|
| 策略选择 | 看目标指纹，决定跑哪些模板、什么参数 | 替代手写 YAML 配置 |
| 结果研判 | 从 UNKNOWN 堆里判断哪些值得人工跟进 | 省人工 |
| 材料撰写 | 把证据包整理成 SRC 提交格式 | 省时间 |

**不要做的事：**不要让 AI 决定"下一步该扫什么"。流水线的执行顺序应该是确定性的 YAML 声明，不是模型现场推理。确定性的东西交给代码，判断性的东西交给模型。

---

## 8. P0：第一个能用的版本

**目标：一条最短的可用链路，跑通即替代你当前的手工流程。**

```
输入 targets.txt
  → subfinder 枚举子域
  → httpx 存活 + 指纹 + 标题
  → nuclei 扫描（severity >= medium）
  → 结果归一化、去重、入库
  → 输出 report.md + findings.json
```

**成功标准（可验证）：**拿 20 个真实域名丢进去，跑一遍出一份整理好的清单，中间不需要人工倒数据。

**代码结构：**

```
redforge/
├── cli.py                    # 命令行入口
├── core/
│   ├── pipeline.py           # 流水线引擎（DAG 调度、条件执行）
│   ├── state.py              # SQLite 状态机、断点续跑、幂等
│   ├── models.py             # Target / Task / Finding / Evidence
│   ├── dedupe.py             # 发现去重聚合
│   └── ratelimit.py          # 并发与速率控制、目标级熔断
├── nodes/
│   ├── base.py               # Node 基类 + 契约校验
│   ├── subfinder.py
│   ├── httpx.py
│   ├── nuclei.py
│   ├── poxiao.py             # 复用已有 MCP
│   ├── ruoyi_scan.py         # 复用已有 Web API
│   └── report.py
├── pipelines/
│   └── web-basic.yaml
├── outputs/
│   ├── markdown.py
│   └── srcreport.py          # SRC 提交格式
└── dsh_plugin/               # P2 再加
    └── index.ts
```

**技术选型：**

| 组件 | 选型 | 理由 |
|------|------|------|
| 语言 | Python 3.12 | 你的存量资产全是 Python，工具生态最好 |
| 并发 | asyncio + 信号量 | 不需要 Celery/Prefect 这类重框架 |
| 状态 | SQLite | 单文件、零部署、够用。数据量大了再换 PG |
| 流水线定义 | YAML + JSONPath | 改流程不改代码 |
| 工具执行 | 先本机子进程，后容器化 | 先跑通，别过早引入 Docker 复杂度 |
| CLI | Typer / Click | 成熟稳定 |

**明确的取舍：**P0 不引入 Docker、不引入消息队列、不做 Web UI。这三样都是"等有真实需求再加"，现在加只会拖慢第一个可用版本的诞生。

---

## 9. 迭代路线

| 阶段 | 内容 | 产出 |
|------|------|------|
| **P0** | CLI 流水线：subfinder → httpx → nuclei → 报告 | 能替代手工流程的可用工具 |
| **P1** | 接入私有工具（poxiao / ruoyi-scan），实现三态判定引擎 | 差异化能力成型 |
| **P2** | dsh 插件化，自然语言驱动 | 符合最初"内置 dsh"的构想 |
| **P3** | Web UI（资产视图、发现视图、运行监控） | 可视化，多人可用 |
| **P4** | 容器化执行、增量调度、模板市场 | 规模化 |

**注意顺序：P1 的三态判定必须在 P2 的 dsh 之前。**先把确定性的东西做扎实，再让模型去用。反过来会做一个"看起来很智能但结论不可信"的东西。

---

## 10. 复用清单（明确边界）

| 项目 | 怎么用 | 许可 |
|------|-------|------|
| subfinder / httpx / nuclei | 直接调用官方二进制 | MIT |
| hexstrike-ai | 工具执行封装思路，或直接挂其 MCP | MIT，可 fork |
| poxiao | 复用其自带 MCP Server | 自有 |
| ruoyi-scan | 复用其 Web API | 自有 |
| asset-survey | CLI 包装 | 自有 |
| dsh-pentest 的六表模型 | **只借鉴设计思路，不抄代码** | 无许可证 |
| dsh-pentester 的 PTES 编排 | **只借鉴设计思路** | Other 许可 |
| dsh 本体 | 作为 P2 的编排外壳 | MIT |

**许可证这条线要守住：无许可证 = 默认保留所有权利。**参考设计思路没问题，复制代码有法律风险，尤其是如果以后想开源分发。

---

## 11. 务实的提醒

**1. 别在 P0 阶段就想着"平台"。**你现在要的是一个能替代手工流程的工具，不是一个能给别人用的产品。前者 1~2 周，后者 6 个月。

**2. 断点续跑要在 P0 就做。**SRC 扫一批域名动辄几小时，中途中断是常态。这个能力一开始不做，后面改起来要动整个架构。

**3. 速率控制不是优化项，是必需项。**SRC 场景下把目标打挂或触发封 IP，等于自毁。P0 就要有全局并发上限和目标级熔断。

**4. 别急着接很多工具。**P0 三个工具（subfinder / httpx / nuclei）足够验证架构。工具接入是加法，架构错了是返工。

**5. 维护成本要算进去。**你 fork 一个第三方项目，上游更新跟不跟？工具升级适配层改不改？所以复用要挑**接口稳定 + 社区活跃 + MIT/Apache 许可**的。

---

*方案结束。下一步：搭 P0 骨架，先跑通 subfinder → httpx → nuclei 这条链路，用真实域名验证。*
