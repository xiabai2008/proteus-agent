# RL 进化链路实测记录（torch 真跑）

> 日期：2026-09-18
> 目的：把"3 个 importorskip 用例至今从未真跑"的状态查清，并复现进化收益
> 解释器（pytest 用的那个）：`<PY312>\python.exe`（Python 3.12.9，pip 25.0.1）
> 原始日志：`data/logs/rl-eval-*.log`、`data/logs/notorch.log`（`data/` 已 gitignore）

## 零、结论摘要

| 步骤 | 结论 |
|---|---|
| 1 装 CPU torch | **无需安装**：torch `2.8.0+cpu` 早在 2026-09-13 就已装在本机 pytest 解释器上；镜像安装为 no-op |
| 2 全量 pytest | **3 个跳过用例已全部真跑通过**：屏蔽 torch 时 165 passed / 3 skipped；torch 就位 173 passed / 0 skipped |
| 3 进化收益复现 | `eval_evolution.py`：**6.0 → 3.0，下降 50%**，与内核 README 声称**完全一致**；`eval_closed_loop.py`：-39%（Q）/ -42%（PPO） |
| 4 文档更新 | `requirements.txt` + `AGENTS.md` 第 3 节已补"已验证（含环境与数据）" |
| 5 本记录 | 见下 |

**要点先说**：这次没有"装 torch"这一步可做——torch 已经在了。真正卡住验证的不是 torch，
而是**评测脚本的外部依赖路径**（07 靶场，见第三节），这也是本文档最有价值的一条。

---

## 一、torch 环境（第 1 步）

### 1.1 实测：已安装，无需安装

```bash
python -c "import sys; print('解释器:', sys.executable)"
python -c "import torch; print('torch.__version__ =', torch.__version__)"
```

```
解释器: <PY312>\python.exe
torch.__version__ = 2.8.0+cpu
```

安装时间（site-packages 目录 mtime）：**2026-09-13 08:32:13** —— 早于本次任务 5 天，
也就是说"3 个用例处于跳过状态"这个前提在本机**已经不成立**了。

`pip list` 相关项：

```
gymnasium  1.3.0
numpy      2.2.5
torch      2.8.0
```

### 1.2 按指令走镜像安装命令：no-op

```bash
python -m pip install torch -i https://mirrors.aliyun.com/pypi/simple/ --dry-run
```

```
Looking in indexes: https://mirrors.aliyun.com/pypi/simple/
Requirement already satisfied: torch in <PY312>\lib\site-packages (2.8.0)
Requirement already satisfied: filelock ... (from torch) (3.17.0)
Requirement already satisfied: typing-extensions>=4.10.0 ... (4.16.0)
Requirement already satisfied: sympy>=1.13.3 ... (1.14.0)
Requirement already satisfied: networkx ... (3.6.1)
Requirement already satisfied: jinja2 ... (3.1.6)
Requirement already satisfied: fsspec ... (2026.4.0)
```

这里我**先做了 `--dry-run` 而不是直接装**，理由是：阿里云 PyPI 镜像上的 `torch`
（`pip index versions torch` 显示最新 2.14.0）默认是 **CUDA 构建**（Windows 上单包约 2.5 GB），
直接 `pip install torch -i <镜像>` 万一触发重装，会把现有的 `+cpu` 构建换掉，还要下几个 GB。
dry-run 结果证明**不会**：已安装的 2.8.0 满足要求，pip 什么都不做。

> 结论：第 1 步的"装"在当前环境下没有实际动作可执行；torch 与 CPU 版语义都符合要求。
> 如果换一台**没装 torch** 的机器，直接跑上面那条镜像命令即可（必要时的官方 CPU 源：
> `pip install torch --index-url https://download.pytorch.org/whl/cpu`）。

---

## 二、全量 pytest：跳过用例确实转真跑（第 2 步）

### 2.1 三处 `importorskip` 守卫

```
tests/test_ppo.py:10        pytest.importorskip("torch", reason="PPO 进化链路需要 torch（可选依赖，未安装时本模块跳过）")
tests/test_closed_loop.py:13 pytest.importorskip("torch", reason="闭环评测含 PPO 层，需要 torch（可选依赖，未安装时本用例跳过）")
tests/test_rl_inject.py:101  pytest.importorskip("torch", reason="PPO 进化链路需要 torch（可选依赖，未安装时本用例跳过）")
```

### 2.2 前后对比（同一解释器、同一代码，只切换 torch 可见性）

"未安装 torch"这一侧**不需要卸载**——用 `sys.modules['torch'] = None` 屏蔽导入即可精确
复现干净环境（`pytest.importorskip` 走的正是 import 失败判定），且不动本机环境：

```bash
# 前（模拟未装 torch）
python -c "
import sys; sys.modules['torch'] = None
import pytest; sys.exit(pytest.main(['-q','-rs']))
"
# 后（torch 就位）
python -m pytest -q -rs
```

| | 用例总数 | 结果 | 跳过项 |
|---|---|---|---|
| 前（屏蔽 torch） | 173 | **165 passed, 3 skipped** | `test_ppo.py:10`（整模块，6 例）、`test_closed_loop.py:13`（1 例）、`test_rl_inject.py:101`（1 例） |
| 后（torch 就位） | 173 | **173 passed, 0 skipped** | 无 |

算术对得上：3 条 skip **条目**覆盖 **8 个**用例（6+1+1），165 + 8 = 173。

> 关于指令里给的"159 passed/3 skipped"：本任务开始前仓库是 167 个用例
> （159 + 8 跳过 = 167），V2 任务新增了 `tests/test_llm_client.py` 的 6 个用例，
> 所以现在是 173。量级一致，差异就是那 6 个新用例。

### 2.3 三个用例逐条真跑（不是只看计数）

```bash
python -m pytest tests/test_ppo.py tests/test_rl_inject.py::test_rank_with_ppo_policy -v
python -m pytest tests/test_closed_loop.py -v
```

```
tests/test_rl_inject.py::test_rank_with_ppo_policy PASSED                [ 14%]
tests/test_ppo.py::test_state_feature PASSED                             [ 28%]
tests/test_ppo.py::test_act_sampling_and_greedy PASSED                   [ 42%]
tests/test_ppo.py::test_update_reduces_loss PASSED                       [ 57%]
tests/test_ppo.py::test_train_ppo_script PASSED                          [ 71%]
tests/test_ppo.py::test_ensure_state_extension PASSED                    [ 85%]
tests/test_ppo.py::test_persistence PASSED                               [100%]
============================== 7 passed in 5.79s ==============================

tests/test_closed_loop.py::test_closed_loop_script PASSED                [ 50%]
tests/test_closed_loop.py::test_evaluate_uses_independent_hosts PASSED   [100%]
============================== 2 passed in 4.79s ==============================
```

**结论**：3 个原本跳过的用例现在**真跑且通过**，无新失败。其中
`test_closed_loop_script` 不只是断言计数——它把 `examples/eval_closed_loop.py` 当子进程
拉起来跑，并断言输出里出现 `PPO`、`47%|39%`、`83%`、`80%`（第 3 节会给出这组数字的来源）。

---

## 三、进化收益复现（第 3 步）

### 3.1 先踩到的坑：脚本直跑必失败

```bash
python examples/eval_evolution.py
```

```
Traceback (most recent call last):
  File "<REPO>\examples\eval_evolution.py", line 22, in <module>
    from warfare.sim import Defense, Host, Service  # noqa: E402
ModuleNotFoundError: No module named 'warfare'
```

`eval_closed_loop.py` 同样（经 `train_policy.py` 第 22 行）：

```
File "<REPO>\examples\train_policy.py", line 22, in <module>
    from warfare.sim import Defense, Host, Service  # noqa: E402
ModuleNotFoundError: No module named 'warfare'
```

### 3.2 根因：07 靶场不在脚本写死的位置

两个脚本都按 `G07 = ROOT.parent / "07-agent-war-range"` 拼路径，
即 `<WS>\07-agent-war-range` ——**该目录不存在**。
真实位置是 `<WS>\网安项目开发规划\07-agent-war-range`（含 `warfare/` 包）。

`conftest.py` 早就处理了这件事：它按
`PENTEST_G07_ROOT` → 相邻布局 → 本机绝对路径（`...\网安项目开发规划\07-agent-war-range`）
的顺序解析，并**注入 `PYTHONPATH`**，供 tests 用 subprocess 拉起的评测脚本继承。
所以：**跑 pytest 时三个用例一直能过，直跑脚本却必然失败**——两者环境不同，这就是"看得见
计数绿、却没人真跑过脚本"的错位来源。

带依赖直跑（本文档用的方式）：

```bash
export G07="<WS>\网安项目开发规划\07-agent-war-range"
PYTHONPATH="$G07" python examples/eval_evolution.py
```

### 3.3 `eval_evolution.py` 输出（与 README 声称对比）

```
================================================================
M3 评测：自我进化效果量化（07 仿真）
================================================================

进化前（探索型）：成功率 5/5，成功平均步数 6.0
进化后（技能型）：成功率 5/5，成功平均步数 3.0
决策步数下降 50%（进化效果）
技能成功率回写: 75% (3/4)
```

对照内核 README（`docs/XPentest内核README.md:60`）的声称：
*"实测决策步数下降 50%（6.0 -> 3.0）"* —— **逐字一致，量级完全吻合**：
6.0 → 3.0，降幅 50%，两次成功率都是 5/5。

**重跑稳定性**：连跑 3 次，4 个数字（6.0 / 3.0 / 50% / 75%）**逐位相同**，无抖动。
脚本用 `shutil` 自建临时数据目录，不在 `data/` 留残留。

### 3.4 `eval_closed_loop.py` 输出（四层叠加）

```
================================================================
闭环回归评测：进化各层叠加收益（07 仿真，30 目标）
================================================================

策略                   成功率      平均步数    收益(步数)
基线(无技能)             83%      4.28       -0%
+技能(直接)             83%      4.40       +3%
+Q学习                83%      2.60      -39%
+PPO                80%      2.50      -42%
+Q学习(兜底)            83%      2.60      -39%
+PPO(兜底)            83%      2.64      -38%

进化收益链：每层相对基线
  +技能(直接)         步数下降 -3%（成功率 83%）
  +Q学习            步数下降 39%（成功率 83%）
  +PPO            步数下降 42%（成功率 80%）
  +Q学习(兜底)        步数下降 39%（成功率 83%）
  +PPO(兜底)         步数下降 38%（成功率 83%）
```

**重跑稳定性**：连跑 3 次，全部 6 行数字**逐位相同**（固定种子 `seed=99` 生成 30 个目标）。

### 3.5 与 README 声称的量级对比（如实说明）

| 指标来源 | 基线步数 | 进化后步数 | 降幅 | 与 README "6.0→3.0 / 50%" 的关系 |
|---|---|---|---|---|
| README 声称（= `eval_evolution.py`） | 6.0 | 3.0 | **50%** | 基准本身 |
| 本机实测 `eval_evolution.py` | 6.0 | 3.0 | **50%** | **完全吻合** |
| 本机实测 `eval_closed_loop.py`（PPO 层） | 4.28 | 2.50 | **42%** | 不同评测，见下 |
| 本机实测 `eval_closed_loop.py`（Q 层） | 4.28 | 2.60 | **39%** | 不同评测，见下 |

**我没有发现需要解释的"不符"**——README 那个 50% 指的就是 `eval_evolution.py`，实测逐字复现。
两个脚本给出不同的降幅（50% vs 42%/39%）是**评测口径不同**，不是数字打架：

- `eval_evolution.py`：5 个固定目标上的**两点对比**（无技能 vs 有技能），衡量"技能沉淀"。
- `eval_closed_loop.py`：30 个随机目标（固定种子）上的**四层叠加**，衡量"技能 + Q + PPO"
  各层边际收益；它的基线是无技能探索序列（4.28 步），而"技能"这一层在这里反而是 **+3%（更差）**，
  真正压步数的是 RL 两层。

值得记一笔的是：把"技能直接"单独看，它**没有**带来步数收益（4.28 → 4.40），
`eval_closed_loop` 里 Q/PPO 的收益也不含"技能本身更快"的贡献。
即"技能进化"的价值在闭环评测里体现为"给 RL 策略提供可选择的动作集"，而不是直接缩短步数。

---

## 四、文档更新（第 4 步）

| 文件 | 改动 |
|---|---|
| `requirements.txt` | 去掉**重复粘贴**的 torch 可选依赖块（原文同一段出现两次）；改为"已验证（含环境与数据）"，写明 pytest 解释器 + torch 版本、屏蔽/就位两组计数、两条安装命令，以及评测脚本需要的 07 `PYTHONPATH` 用法。**torch 仍不在安装列表内**（保持可选依赖定位，硬规则 5） |
| `AGENTS.md` 第 3 节 | 新增两条关键事实：① RL 进化链路**已验证**（环境 torch 2.8.0+cpu、数据 165/3 → 173/0、6.0→3.0 与 -39%/-42%）；② 外部依赖 **07 靶场的真实路径**在 `网安项目开发规划\` 下、`conftest.py` 的解析顺序、直跑必须自行设 `PYTHONPATH` |

> 说明：指令里说"把……从'未验证'更新为'已验证'"——实测 `requirements.txt` 与
> `AGENTS.md` 原文里**都没有"未验证"字样**（`AGENTS.md` 第 3 节此前完全没有 torch 条目）。
> 所以这里做的是**补上已验证记录**，而不是替换一个不存在的措辞；`requirements.txt` 里
> 顺带修了一处真实缺陷（重复块）。

---

## 五、问题清单

### F1（低）`requirements.txt` 的 torch 可选依赖块重复粘贴

**现象**：同一段 4 行注释（`# 可选依赖：RL 进化链路…`）连续出现两次。
**根因**：编辑时重复粘贴，无功能影响。
**修复（已做）**：合并为一段，并补上验证结论。

### F2（中）评测脚本直跑必失败：外部依赖路径与脚本内写死的候选不符

**现象**：`python examples/eval_evolution.py` / `eval_closed_loop.py` 直接跑均报
`ModuleNotFoundError: No module named 'warfare'`；但 `pytest` 下对应的用例却通过。
**根因**：脚本内 `G07 = ROOT.parent / "07-agent-war-range"` 指向
`<WS>\07-agent-war-range`（不存在）；真实路径在
`<WS>\网安项目开发规划\07-agent-war-range`。`conftest.py` 有第二个候选路径并注入
`PYTHONPATH`，只有经 pytest 拉起的子进程才继承得到，直跑拿不到。
**修复（未改代码，已落文档）**：两个评测脚本的路径解析依赖 `PYTHONPATH` 兜底；已在
`requirements.txt` 与 `AGENTS.md` 第 3 节写明"直跑要自行设 `PYTHONPATH`"及真实路径。
彻底修法是让脚本也读 `PENTEST_G07_ROOT`（与 `conftest.py` 同一优先级链），
但改脚本会动被测对象，本次只记录。

### F3（低）内核 README 的用例数与现状不符

**现象**：`docs/XPentest内核README.md:71` 写"36 个用例"，实际收集到 **173** 个。
**根因**：README 是 fork 自源仓库的旧文档，未随阶段二/三的测试增长更新。
**修复（未做）**：属文档陈旧，且不在本次指令的更新范围内（指令只点名
`requirements.txt` 与 `AGENTS.md` 第 3 节）。建议后续一并刷新。

---

## 六、未覆盖与遗留

1. **换机安装未实测**：本次机器上 torch 已就位，因此"从零安装 CPU torch"这条路径没有真正
   执行过（只做了 dry-run 证明不会重装）。要验证安装路径本身，需要一台干净机器或临时 venv。
2. **CUDA 版未验证**：全部结论基于 CPU 构建 `2.8.0+cpu`。
3. **PPO 训练的可复现性只验到"同机同版本逐位一致"**：3 次重跑一致，但未跨机器/跨 torch
   版本比对，不能推断为跨环境确定性。
4. **07 靶场的 `warfare` 包内容未审计**：本次只把它作为仿真依赖使用（`sim.py` 的
   `Host/Service/Defense`），未审查其实现。

---

## 七、依赖边界（硬规则 5 自查）

- `requirements.txt` 的**安装列表仍只有 `PyYAML` 与 `pytest`**；torch 只以注释形式出现，
  明确标注"可选依赖"。
- 未安装 torch 的环境：`pytest.importorskip` 让 3 处用例跳过，其余 165 个用例照常通过
  （第二节实测数据），**不阻塞**内核主功能。
- 本次未引入任何新依赖；`numpy` / `gymnasium` 是 torch 的连带依赖，非本项目直接引入。
