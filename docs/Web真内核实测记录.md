# Web 控制台真内核驱动实测记录

> 日期：2026-09-17　　目标：`http://127.0.0.1:8080`（授权本地演示靶子 `examples/target.py`）
> 驱动：`driver=penagent`（真内核 + LLM 决策循环；scripted 离线驱动此前已验证过）
> 模式：`pentest-standard` 与 `ctf-web`，同一内核、同一目标
> 原始日志：`data/logs/`（`data/` 已 gitignore，未入库）

## 零、结论摘要

| 步骤 | 结论 |
|---|---|
| 1 拷贝 `.env` | 完成：三个键写入本仓库 `.env`（已 gitignore），全程未打印 key |
| 2 拷贝 `examples/target.py` | 完成：与源仓库逐字节一致，仅用 stdlib，无新依赖 |
| 3 CLI 直连 | **通过**：`success`（5 步），结论带 `证据引用: seq=[1, 2, 3, 4]` |
| 4 Web 下发（pentest-standard） | **通过**：4 步流 + verdict `success`，证据链 `integrity.ok=true` |
| 5 Web 下发（ctf-web，同目标） | **判定不同已证实**；但该次运行本身两次都没跑出一份干净结论（见 F4） |

链路是通的：LLM 决策、工具调用、证据链、SSE 步骤流、判定器都真实工作。过程中查出
**6 个问题**，其中 2 个是我为打通链路必须修的（F1/F2），其余 4 个只记录（F3~F6）。

| 编号 | 严重度 | 一句话 | 处置 |
|---|---|---|---|
| F1 | **高** | LLM 端点要求 `x-opencode-session`，客户端不送 → 全链路 400，一行都跑不了 | **已修**（`penagent/llm.py`） |
| F2 | 中 | LLM 读超时抛的 `TimeoutError` 未被捕获，不重试且直接掀翻整个任务 | **已修**（`penagent/llm.py`） |
| F3 | 中 | Web 真内核驱动与前端 30 秒等待不匹配：`mission_id` 只在子进程退出后才发布 | 记录 |
| F4 | 中 | prompt 要求严格 JSON，模型会改吐原生工具调用标记（DSML），解析失败即整个任务判失败 | 记录 |
| F5 | 低 | `/api/mission/<mode>/<id>` 路由切片写错，恒定 404（前端未使用，属潜在缺陷） | 记录 |
| F6 | 低 | 函数型工具静默丢弃未知参数，模型猜错参数名时得到空输出+无错误信息 | 记录（V1 已报 F5，本次在真机复现） |
| F7 | **高** | `ctf-web` 的 `python_solve` 是宿主直跑、无路径约束的任意代码执行；模型自发枚举了 D: 盘根目录与 `/proc` | 记录（属模式设计，但后果需知会） |

---

## 一、环境准备

### 1.1 拷贝 LLM 凭据（不打印 key）

源仓库 `.env` 有三个键。用脚本按键拷贝，只打印键名与长度，值一律不落到输出：

```bash
python -c "
from pathlib import Path
src = Path(r'<WS>\网安项目开发规划\10-pentest-agent\.env')
dst = Path(r'<REPO>\.env')
KEYS = ['PENTEST_LLM_BASE_URL', 'PENTEST_LLM_API_KEY', 'PENTEST_LLM_MODEL']
...  # 逐键读写
"
```

输出（仅键名与长度）：

```
已写入: <REPO>\.env
  PENTEST_LLM_BASE_URL   长度= 29
  PENTEST_LLM_API_KEY    长度= 67
  PENTEST_LLM_MODEL      长度= 17
源 .env 中共有键数: 3
缺失非空值: 无
```

**结论**：三个键齐备。`.env` 在 `.gitignore` 内（第 2 行 `.env`），不会入库。
**修复**：无。

### 1.2 拷贝演示靶子

`examples/target.py`（授权本地靶子）从源仓库拷贝，用 Write 工具落盘（Mimosa 拦截了
`cp`——直接 `cp` 会绕过写入前的扫描，要求改用 Write/Edit，已照办）。

```bash
diff "<源>/examples/target.py" examples/target.py   # 无输出 → 逐字节一致
grep -nE "^import |^from " examples/target.py
```

```
11:import argparse
12:import sys
13:from http.server import BaseHTTPRequestHandler, HTTPServer
```

**结论**：逐字节一致；只用 stdlib（`argparse`/`sys`/`http.server`），**不引入新依赖**；
且只绑定 `127.0.0.1`。
**修复**：无。

靶子自带 5 个端点：`/`（title 自述 Flask/2.3）、`/robots.txt`（Disallow `/admin`、`/debug`）、
`/health`、`/admin`（401）、`/debug`（200，返回版本信息）。

---

## 二、LLM 链路：首次失败 → 定位 → 修复

### 2.1 首次 CLI 直连：失败

```bash
python -m penagent run --target http://127.0.0.1:8080 \
  --objective "被动侦察：识别首页技术栈，抓取 robots.txt，探测 /admin 与 /debug，输出带证据引用的结论" \
  --mode pentest-standard --targets 127.0.0.1 --authorize --max-steps 10
```

输出（`data/logs/v2-cli-run.log`）：

```
任务结果: failed（步骤 1）
总结: LLM 调用失败: LLM API HTTP 400: {"type":"error","error":{"type":"MissingSessionID",
      "message":"Error from provider (Console Go): Request is missing x-opencode-session
      and cannot be routed efficiently. ..."}}
证据引用: seq=[]
```

**根因**：`.env` 的 `PENTEST_LLM_BASE_URL` 指向 `https://opencode.ai/zen/go/v1`（29 字符，
与内核默认的 `/zen/v1` 不同）。该端点要求每个会话带稳定 id。端点官方文档原文：
*"Send a stable session ID in x-opencode-session for each conversation"*。内核的
`penagent/llm.py` 只发 `Authorization` / `Content-Type` / `User-Agent`，因此 400。

**修复**：`LLMConfig` 增加 `session_id`（`uuid4().hex`，按 config 实例稳定 = 一次任务一个会话），
请求头带上 `x-opencode-session`。

### 2.2 修复后：模型是推理模型，token 预算会吃掉正文

单次直连验证时用小 `max_tokens` 复现了另一个坑：

```
LLMError: LLM 返回空内容，重试
```

抓原始响应看清了原因——`deepseek-v4-flash` 是**推理模型**，响应多一个 `reasoning_content`，
且 **reasoning token 计入 `max_tokens`**：

```
finish_reason: stop
message 键: ['role', 'content', 'reasoning_content']
  content = '通了'
usage: {'completion_tokens': 114, 'completion_tokens_details': {'reasoning_tokens': 112}}
```

`max_tokens=20` 时 20 个 token 全被推理吃掉 → `content` 为空 → 内核判"返回空内容"。
内核所有调用点都用默认 `max_tokens=4096`，够用，故这条只作观察记录、未改动。

顺带确认模型 id 有效（`GET /models` 返回 38 个模型，`deepseek-v4-flash` 在列表中）。

### 2.3 第二次失败：读超时掀翻整个任务（Web 路径暴露）

Web 下发的一次运行跑到第 16 步后卡住约 10 分钟，最终状态：

```
status = error
error  = 内核退出码 1: ... File "<PY312>\Lib\ssl.py", line 1251, in recv_into
         TimeoutError: The read operation timed out
```

**根因**：`socket.timeout`（= `TimeoutError`）在**连接阶段**会被 `urllib` 包成 `URLError`，
但在 `resp.read()` **读取阶段**抛的是裸 `TimeoutError`，它不是 `URLError` 的子类，
所以没被 `chat()` 的 `except urllib.error.URLError` 命中 → 不重试、直接冒泡 →
`python -m penagent run` 退出码 1 → 整个任务失败，白跑 16 步。

**修复**：`chat()` 补 `except (TimeoutError, OSError)` 分支，与其余失败一样走退避重试。
（`HTTPError`/`URLError` 分支在前，仍优先命中，行为不变。）

---

## 三、CLI 直连验证（真内核 + LLM 决策）

```bash
python -m penagent run --target http://127.0.0.1:8080 \
  --objective "被动侦察：识别首页技术栈，抓取 robots.txt，探测 /admin 与 /debug，输出带证据引用的结论" \
  --mode pentest-standard --targets 127.0.0.1 --authorize --max-steps 10
```

> `--authorize` 是必需的：`pentest-standard` 的 `permission.default = ask`，未授权时
> 每个工具都会以"待人工确认"被拒（机制性生效，非提示词约束）。

### 每一步工具调用（`data/logs/v2-cli-run2.log`）

| 步 | 工具 | 参数 | 关键输出 |
|---|---|---|---|
| 1 | `http_probe` | `url=http://127.0.0.1:8080/` | 200，`Server: demo-portal`，title `Demo Portal - Flask/2.3` |
| 2 | `robots_fetch` | `base_url=http://127.0.0.1:8080` | 200，`disallow: ["/admin","/debug"]` |
| 3 | `http_probe` | `url=.../admin` | 401，`Server: BaseHTTP/0.6 Python/3.12.9` |
| 4 | `http_probe` | `url=.../debug` | 200，`Content-Type: text/plain`，65 字节 |

### 最终结论（节选）

```
任务结果: success（步骤 5）
证据引用: seq=[1, 2, 3, 4]
```

结论正文按"已验证事实 + 证据（seq）"组织，并显式把未验证项分开：

> 【已验证事实 + 证据】
> 1. 首页（seq 1，工具 http_probe）：HTTP 200 … title = "Demo Portal - Flask/2.3" → 技术栈判定为 Python Flask 2.3
> 2. robots.txt（seq 2…）：disallow 列表 = ["/admin", "/debug"]
> 3. /admin（seq 3…）：HTTP 401 …
> 4. /debug（seq 4…）：HTTP 200 … **本阶段工具未取回正文，故不作断言**
>
> 【未验证 / 仅供后续线索（不作结论）】
> - /admin 的 Server 头与首页不一致 …需主动测试阶段进一步确认

**结论**：**通过**。结论**带证据引用**（`seq=[1,2,3,4]`），且反幻觉语义生效——模型拒绝
在没取回正文的情况下断言 `/debug` 泄露敏感信息，把它列进"未验证"。

**修复**：无（这次运行本身没问题；使它跑得起来的是 2.1 / 2.3 的两处修复）。

---

## 四、Web 控制台真内核驱动

### 4.1 起控制台

```bash
python web/server.py --port 8770
```

```
Proteus 控制台: http://127.0.0.1:8770/  (data=<REPO>\data)
```

`GET /api/modes` 三个模式与各自判定器：

```
ctf-crypto          CTF Crypto 模式  verifier={'type': 'flag_regex', 'pattern': '(?i)(flag|ctf)\\{[^}]+\\}', ...}
ctf-web             CTF Web 模式     verifier={'type': 'flag_regex', 'pattern': '(?i)(flag|ctf)\\{[^}]+\\}', ...}
pentest-standard    常规渗透测试模式  verifier={'type': 'evidence_chain', 'pattern': None, 'require_poc': True}
```

### 4.2 下发（按前端真实流程）

前端 `web/static/app.js` 的流程是：`POST /api/tasks` → 轮询 `/api/state/<key>` 拿
`mission_id`（最多 60 次 × 500ms）→ `EventSource /api/stream/<mission_id>?mode=...`。
下面用 curl 复刻同一条路径。

```bash
curl -s -X POST http://127.0.0.1:8770/api/tasks -H 'Content-Type: application/json' \
  --data-binary @data/logs/v2-web-payload.json
```

```json
{"key": "pentest-standard-1789655988395", "mode": "pentest-standard", "driver": "penagent",
 "mission_id": "", "status": "running", "error": "", "started_at": 1789655988.4}
```

轮询 `/api/state/<key>`：**+20 秒**拿到 `mission_id=c8e4b600 status=finished`。

### 4.3 步骤流与判定（SSE）

```bash
curl -s -N --max-time 60 "http://127.0.0.1:8770/api/stream/c8e4b600?mode=pentest-standard"
```

事件分布：`{'step': 4, 'verdict': 1}`。步骤与 CLI 路径同源（同一内核）：

| 步 | 工具 | ok | 关键输出 |
|---|---|---|---|
| 1 | `http_probe` | True | 200，`Server: demo-portal`，Content-Length 120 |
| 2 | `robots_fetch` | True | 200，`disallow: ['/admin','/debug']` |
| 3 | `http_probe` | True | 401，`Server: BaseHTTP/0.6 Python/3.12.9` |
| 4 | `http_probe` | True | 200，`text/plain`，65 字节 |

判定事件：

```
outcome = success
flag    = ''
steps   = 4
summary = 结论（被动侦察，目标 http://127.0.0.1:8080）：
          【证据序号 ↔ 工具输出映射】[1]…[2]…[3]…[4]…
          【风险判定】- /admin：401 = 已受认证保护 … 置信：已验证为受保护
                      - /debug：未认证即 200 … 但正文内容本次未被捕获 …
                        "是否泄露敏感信息" **未验证，不下结论**
          …【置信度】…｜证据链校验通过
```

### 4.4 证据链视图

```bash
curl -s "http://127.0.0.1:8770/api/evidence/pentest-standard/c8e4b600"
```

```
integrity = {"ok": true, "length": 63, "tampered": [], "broken_links": []}
total     = 63
mission   = {"id": "c8e4b600", "outcome": "success", "blocked_steps": []}
conclusion= {"seq": 63, "kind": "conclusion", "content": {"summary": "结论（被动侦察…"}}
```

**结论**：**通过**。真内核驱动在 Web 侧完整走通：下发 → 步骤流 → 判定 → 证据链，
链式哈希校验 `ok=true`、无篡改、无断链，收口结论落成 `kind=conclusion` 的证据记录。

**修复**：无。但本轮暴露两个流程问题（F3、F5），见第七节。

---

## 五、同一目标的 ctf-web 模式对比

同样通过 Web 下发，`mode=ctf-web`、`driver=penagent`、同一 `http://127.0.0.1:8080`。

### 5.1 模式闸门：机制性差异（直接查裁决，不靠推断）

```
pentest-standard: 模式注册表 20 → 白名单过滤后 20
    ['dalfox_xss', …, 'http_probe', …, 'nuclei_scan', 'robots_fetch', …, 'sqlmap_auto', …]
    verifier=evidence_chain require_poc=True pattern=None
    budget.max_steps=40 memory_ns=pentest-standard sandbox=docker

ctf-web: 模式注册表 25 → 白名单过滤后 5
    ['codec_chain', 'codec_decode', 'file_type', 'python_solve', 'rsactf_attack']
    verifier=flag_regex require_poc=False pattern='(?i)(flag|ctf)\\{[^}]+\\}'
    budget.max_steps=60 memory_ns=ctf-web sandbox=local
```

逐工具裁决（`capability.allows` + `permission.level_for`）：

| 工具 | pentest-standard | ctf-web |
|---|---|---|
| `http_probe` | allow / ask | **DENY**（不在本模式） |
| `robots_fetch` | allow / ask | **DENY** |
| `nuclei_scan` | allow / ask | **DENY** |
| `sqlmap_auto` | allow / ask | **DENY** |
| `fscan_scan` | allow / ask | **DENY** |
| `python_solve` | allow / ask | allow / ask |
| `codec_decode` | allow / ask | allow / ok（auto_approve） |
| `file_type` | allow / ask | allow / ok（auto_approve） |
| `rsactf_attack` | allow / ask | allow / ask |

这说明两件事：**同一内核、同一目标，工具集与判定器由 ModeProfile 机制性决定**；
且 ctf-web 的 web 侦察工具（`http_probe`/`robots_fetch`）**被自己的白名单挡在外面**，
模型只能用 `python_solve` 自己写脚本发请求（实测它就是这么做的）。

### 5.2 ctf-web 实际运行

第一次（`0c84911f`，1 步）——被判 `failed`，但**不是**判定器的功劳：

```
step 1 | python_solve | ok=True   # 脚本抓 / 与 /robots.txt，200
verdict: outcome=failed, flag='', steps=1
summary: LLM 调用失败: LLM 输出不是合法 JSON: Expecting value: line 1 column 1 (char 0)
         ---
         <｜｜DSML｜｜ calls><｜｜DSML｜｜ invoke name="python_solve">…
```

**根因**（F4）：两个模式的 prompt 都写明"输出严格 JSON"，但模型第 2 次决策改吐了**原生
工具调用标记**（DSML 语法的 `<|DSML|invoke name="python_solve">`），`chat_json()` 按 JSON
解析失败 → 任务直接判 `failed`。

第二次（`c5d2d821`）行为正常得多：连续 19 步全部是 `python_solve`，脚本化地遍历
`/`、`/robots.txt`、`/admin`、`/debug` 及 `/flag`、`/login`、`/debug/config`、cookie 伪造等
方向找 flag——**这正是 CTF 模式的 solve-or-die 姿态**（`budget.max_steps=60`，远大于
pentest 的 40）。靶子上本来就没有 flag，所以它一直在找。

**这一次由我在第 19 步主动终止**，理由有二，都记在这里：

1. 成本：按 ~1 分钟/步的节奏，跑满 60 步还要约 40 分钟付费 LLM 调用，而靶子上**确无
   flag**（`examples/target.py` 源码里没有任何 flag 字样），继续跑不会再产出新证据。
2. 更重要的原因：它开始**枚举宿主机文件系统**（见 F7）——第 19 步的脚本 `os.walk`
   了 `/app`、`/srv`、`/home`、`/root` 等 Linux 路径（在 Windows 上不存在，故 `HITS 0`），
   随后打印了 `os.listdir('/')`（在 Windows 上解析为当前盘根 = `D:\`）与 `/proc` 列表。
   继续让它跑下去，没有验证价值，只有"在用户机器上乱翻"的风险。

终止方式与结果：

```
Stop-Process -Id <penagent run 的 PID> -Force
→ /api/state/<key>: status=error, error="内核退出码 4294967295"（= -1，被强杀）
→ 作战记录 data/missions/ctf-web/c5d2d821.json 的 outcome 仍停在 "running"
```

> 附带发现：控制台**没有取消/对账机制**——被强杀的任务在 `_missions` 里变 `error`，
> 但内存里的作战记录永远停在 `running`，界面上会一直显示"进行中"。

### 5.3 ctf-web 在本次实测中的最终结果

| 运行 | 步数 | outcome | flag | 判失败/成功的原因 |
|---|---|---|---|---|
| `0c84911f` | 1 | `failed` | `''` | LLM 第 2 次决策吐 DSML 而非 JSON（F4） |
| `c5d2d821` | 19 | 未收口（被我终止） | — | 靶上无 flag，模型持续搜寻 |

两次都**没有得到"`flag_regex` 收到一份合法结论时如何判定"的干净样本**（见第八节）。

### 5.4 判定差异对照表

| 维度 | pentest-standard | ctf-web |
|---|---|---|
| 判定器 | `evidence_chain` | `flag_regex` |
| 判据 | 证据链完整性 + `require_poc=True`（每步可追溯到工具真实输出） | 结论文本里命中 `(?i)(flag\|ctf)\{[^}]+\}` |
| 实测 verdict 字段 | `outcome=success`，`summary` 内嵌 `[1]…[4]` 证据序号，尾注"证据链校验通过" | `outcome=failed`，`flag=''`（未命中） |
| 链式校验 | `integrity.ok=true`，63 条记录，无篡改/断链，`conclusion` 落 seq 63 | 不适用（不建证据链结论） |
| 判失败的形态 | 结论缺证据引用或引用不存在的 seq | 文本里找不到形如 `flag{...}` 的串 |
| 工具面（实测） | 20 个（含 `http_probe`/`robots_fetch`/`nuclei_scan`/`sqlmap_auto`） | 5 个（`python_solve`/`codec_*`/`file_type`/`rsactf_attack`） |
| 同目标行为 | 4 步被动侦察后收口，给出"已验证/未验证"分离的结论 | 19 步脚本化搜寻 flag（含枚举宿主文件系统），未果 |

**差异是机制性的**：判定器类型、判据、工具白名单、步数预算、记忆分区全部由 ModeProfile
决定；同一内核同一目标下，两种模式对"任务是否成功"的回答方式完全不同——一边要求
"结论可追溯到证据"，另一边只问"flag 在哪"。

---

## 六、问题清单

### F1（高）LLM 端点要 `x-opencode-session`，客户端不送 → 全链路 400

**现象**：`python -m penagent run` 第一次调用 LLM 即失败：
`LLM API HTTP 400 ... MissingSessionID ... Request is missing x-opencode-session`。
**根因**：`.env` 指向 `https://opencode.ai/zen/go/v1`，该端点要求每会话一个稳定 id
（官方文档原文要求），而 `penagent/llm.py` 只发 Authorization/Content-Type/User-Agent。
**修复（已做）**：`LLMConfig.session_id`（`uuid4().hex`，按 config 实例稳定）+
请求头 `x-opencode-session`。

### F2（中）LLM 读超时未被捕获 → 不重试且掀翻整个任务

**现象**：Web 下发的一次运行跑到第 16 步后挂约 10 分钟，最终 `status=error`：
`TimeoutError: The read operation timed out`（`ssl.py: recv_into`）。
**根因**：`socket.timeout` 在连接阶段被包成 `URLError`，但在 `resp.read()` 阶段是裸
`TimeoutError`，不是 `URLError` 子类 → `except urllib.error.URLError` 接不住 →
不重试、直接冒泡 → CLI 退出码 1 → 整个任务失败。
**修复（已做）**：补 `except (TimeoutError, OSError)` 分支，纳入既有退避重试。

### F3（中）Web 真内核驱动与前端 30 秒等待不匹配

**现象**：`mission_id` 在 `/api/state/<key>` 上长时间为空；只在 `python -m penagent run`
子进程**退出后**才出现。前端 `app.js` 最多等 60×500ms = **30 秒**就放弃并报
"内核未返回作战记录 id"。实测：正常的一次 pentest 运行约 20 秒（勉强够），
但 ctf-web（60 步预算）与任何长任务都远超 30 秒；步骤流因此根本打不开。
**根因**：`web/server.py::_run_cli` 用 `subprocess.run(...)` 阻塞等待，再从 stdout 里正则
抠 `作战记录: <path>` 拿 mission id——id 天然只在跑完后才可得。而按内存里的作战记录看，
**运行中的步骤其实是实时的**（`data/missions/<ns>/<id>.json` 边跑边写）。
**修复（建议，未做）**：让 `_run_mission` 先起进程、立刻从内存目录里发现"新出现的
running 记录"以发布 `mission_id`，再 `wait()`；同时给 `_run_cli` 加 `--max-steps` 上限与
超时。改 `web/server.py` 会改变被测对象，本次只记录。

### F4（中）严格 JSON 协议 vs 模型的原生工具调用习惯

**现象**：ctf-web 第一次运行第 2 次决策，模型输出 DSML 工具调用标记而非 JSON，
`LLM 输出不是合法 JSON: Expecting value: line 1 column 1` → 任务判 `failed`。
**根因**：两个 prompt 都要求"输出严格 JSON"，且把工具清单以文本 `{tools}` 注入；
本模型在见到工具清单时倾向直接吐原生 tool-call 标记。`chat_json()` 只做 JSON 提取，
不做"原生工具调用标记 → 工具调用"的兜底解析。
**修复（建议，未做）**：解析层增加对原生 tool-call 标记的降级解析，或改用 API 原生
tools 参数而非把工具清单塞进 prompt。

### F5（低）`/api/mission/<mode>/<id>` 路由切割错误，恒定 404

**现象**：`GET /api/mission/pentest-standard/69c51a4f` → 404 `未知模式: mission`。
**根因**：`web/server.py` 里 `_, _, mode_id, mission_id = route.split("/", 3)`。
`split("/", 3)` 对 `/api/mission/pentest-standard/69c51a4f` 只切出 4 段
`['', 'api', 'mission', 'pentest-standard/69c51a4f']`，于是 `mode_id` 被赋成 `'mission'`、
`mission_id` 被赋成 `'pentest-standard/69c51a4f'`。应为 `split("/", 4)`。
**影响**：前端未调用该端点（只用 `/api/stream`、`/api/evidence` 等），故属潜在缺陷。
**修复（建议，未做）**：改 `maxsplit=4`。

### F6（低）函数型工具静默丢弃未知参数（真机复现）

**现象**：模型给 `robots_fetch` 传 `url`（schema 声明的是 `base_url`），参数被静默丢弃，
返回 `ok=False` + 空输出 + Python 缺参 TypeError 文本；大批 CLI 工具（`gobuster_dir`、
`nuclei_scan`、`ffuf_fuzz`、`dalfox_xss`、`pocsuite_poc`、`rayscan_scan` 等）在模型用错
参数名时同样返回 `ok=False` 且输出为空，**模型看不到失败原因**，于是反复换工具试。
**根因**：`penagent/tools.py::ToolRegistry.execute` 先按 `spec.parameters` 过滤实参再调用，
缺参与未知参数都不做前置校验（V1 实测记录 F5 已报同一条，本次是它在真机里的后果）。
**修复（建议，未做）**：执行前校验必需参数并返回明确的"未知/缺失参数"错误。

---

### F7（高）`ctf-web` 的 `python_solve` 是宿主直跑、无路径约束的任意代码执行

**现象**：ctf-web 运行到第 19 步时，模型自己写了一段脚本：

```python
import os,re,glob
pat = re.compile(rb'flag\{[^}]{0,80}\}|CTF\{[^}]{0,80}\}')
roots = ['/app','/srv','/opt','/home','/root','/tmp','/var/www','/usr/src','/workspace','/data','/ctf']
for r in roots:
    for dp,dn,fn in os.walk(r): ...      # 全盘遍历，只跳过 /proc /sys node_modules /.git
...
print('HITS', len(hits))
print('---cwd---', os.getcwd())
print('---root---', os.listdir('/'))      # Windows 上 / 解析为当前盘根 → D:\
print('---proc---') ... open('/proc/%s/cmdline')
```

实测输出（节选）：

```
HITS 0
---cwd--- <REPO>
---root--- ['$RECYCLE.BIN', '.pnpm-store', '2255d0e62002f2dc876d6fb36d3daee6', '5EDemocache',
            'AndrowsData', 'baidu', 'BaiduNetdiskDownload', 'c', 'CloudMusic', 'code_AI', ...]
```

`os.walk` 走 Linux 路径在 Windows 上自然扑空（`HITS 0`），但 `os.listdir('/')` 与 `/proc`
枚举**成功返回了宿主 D: 盘的根目录清单**——里面是用户的个人目录。

**根因**：`modes/ctf-web.yaml` 的 `sandbox: local`（模式文件注释写明"CTF 解题脚本走宿主
直跑档，换 docker 即启用容器隔离"），而 `python_solve` 是 `subprocess` 直跑脚本、**没有
工作目录约束、没有路径沙箱、没有只读挂载**。也就是说：CTF 模式给模型的不是"一个解题
工具"，而是"宿主上的任意代码执行"。

**影响面（为什么定级高）**：这条路与另外两处叠加后，闸门是敞开的——
`python_solve` 在 ctf-web 的权限档位是 `ask`，但只要 `--authorize`（Web 下发的
`authorize=true` 就是）就放行；而 V1 已证实 `proteus-ctf` 档是 `approval: never`；
本记录 F1 又显示内核侧的 MCP 底层入口不过 Policy。于是"不弹审批 + 内核不设防 +
宿主直跑"三者同时成立。

**修复（建议，未做）**：把 `ctf-web` 的 `sandbox` 从 `local` 换成 `docker`（字段已支持，
`build_sandbox` 已在 `PenAgent` 构造时挂到注册表），或给 `python_solve` 加工作目录约束与
路径只读策略。改 `modes/ctf-web.yaml` 会改变被测模式的行为，本次只记录。

---

## 七、本次改动

| 文件 | 改动 | 理由 |
|---|---|---|
| `penagent/llm.py` | `LLMConfig` 增 `session_id`；请求头加 `x-opencode-session` | F1：不加则一行都跑不了 |
| `penagent/llm.py` | 端点协议白名单（仅 http/https，与 `mcp_client.ALLOWED_SCHEMES` 同约定） | 请求侧加固；**刻意不阻断环回/私网**——`base_url` 来自操作员 `.env`，本地 OpenAI 兼容端点（ollama/vLLM 跑在 127.0.0.1）是正当配置，`mcp_client.py` 已有同样取舍的注释 |
| `penagent/llm.py` | `except (TimeoutError, OSError)` 纳入重试 | F2：读超时不再掀翻整个任务 |
| `examples/target.py` | 新增（从源仓库逐字节拷贝） | 指令第 2 条 |
| `.env` | 新增（三键，已 gitignore） | 指令第 1 条 |

未改动：`web/server.py`（F3/F5 的根因在这里，但它是本次的被测对象，改了就不再是"实测"）。

---

## 八、未覆盖与遗留

1. **ctf-web 没有干净样本**：两次真机运行——一次因 F4（DSML）在第 1 步判失败，一次跑到
   19/60 步被我主动终止（理由见 5.2：靶上确无 flag + 模型开始枚举宿主文件系统）。因此
   "`flag_regex` 收到一份合法结论时会怎么判"缺少一次端到端观测；判定差异目前由 5.1 的
   裁决元数据与 verdict 字段形态（`outcome`/`flag`）支撑，**不是**由一次成功的 CTF 收口
   样本支撑的。要补这一课，需要一个真带 flag 的靶子。
2. **控制台无取消/对账**：本次强杀内核后，`/api/state` 变 `error`（退出码 4294967295），
   但内存里的作战记录永远停在 `running`，界面会一直显示"进行中"。控制台没有 cancel
   端点，也没有启动时对账"running 记录是否还有活进程"。
3. **前端 UI 未用浏览器验收**：本次用 curl 复刻了 `app.js` 的调用序列，未开浏览器点按钮。
4. **`failOnStartupError` / DSH 侧审批档位**不属本次范围（见 `docs/DSH宿主实测记录.md`）。
5. **环境观察**：8770 端口上同时存在两个 `web/server.py`（一个起于本会话 22:19，另一个
   起于上一会话 15:50 一直没退）。两者代码相同（`web/server.py` 自 15:49 未再改动，且每个
   任务都会新起子进程重新 import），故不影响本次结论；但 `_missions` 是**进程内**状态，
   两个实例各有一份，建议只保留一个实例再做 UI 验收，否则可能看到互相矛盾的战斗记录列表。
6. **靶子响应的双 `Server` 头**：`examples/target.py` 的 `BaseHTTPRequestHandler` 会先发一个
   `Server: BaseHTTP/0.6 Python/3.12.9`，脚本又追加 `Server: demo-portal`，于是同一个响应
   有两个 `Server` 头。`http_probe` 在 2xx 路径取 `dict(items())`（后者胜出 → `demo-portal`），
   在 `HTTPError`（401）路径取 `exc.headers.get("Server")`（前者胜出 → `BaseHTTP/0.6…`），
   于是同一目标的 `Server` 字段在 200 与 401 上不一致。两次运行的模型都把它当成"架构线索"
   并明确标注为**未验证**——反幻觉语义按预期工作，这条本身不是问题，仅记录成因以免误读为
   真实差异。

---

## 九、安全边界说明

- 内核的网络动作全程只对 `127.0.0.1:8080`（本仓库自带的授权演示靶子）；Web 驱动的
  `_run_cli` 也把 `--targets` 硬编码为 `127.0.0.1`。
- **但工具侧不止于网络**：ctf-web 模式的 `python_solve` 在宿主直跑且无路径约束，实测中
  模型自发读到了宿主盘根目录清单（F7）。这一点已在本次实测中暴露并终止（见 5.2），
  特此记录以免把"只打回环"误当成"只能碰靶子"。
- LLM 凭据仅写入本机 `.env`（gitignore），**未**出现在任何对话输出或本文档中；代码改动
  涉及的请求侧加固见第七节。
- prompt 注入与工具输出均来自本地靶子，不含外部不可信内容。
