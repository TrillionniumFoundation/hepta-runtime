# 真实 Hepta Neuron checkpoint 的原生持久闭环：本地资格结果

## 结论与身份

本地闭环已经通过两种 feature 模式的实际执行。最终源是 `65ae015f0ccee9366f29d4477ce9a9015682b6c0`，Draft PR 为 [hepta-runtime #150](https://github.com/TrillionniumFoundation/hepta-runtime/pull/150)，精确 CI 为 [45006849470](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45006849470)。两种模式均通过 6 个单元测试和 1 个启动真实非 `cfg(test)` parser 二进制的集成测试，然后各执行一次冻结的真实 checkpoint campaign。

这里完成的是研究执行资格：来自同一认证来源的五个真实 checkpoint，经重新认证、语义快照、EditProgram 重新编译、既有 canonical artifact owner 发布、完整任务评价、明确接受或拒绝、原字节逆向恢复，最后由新进程的下一任务读取实际恢复件。接受决定没有写入服务或活动模型指针。

完整原始结果在 `campaign_attempt004/`。计划在首次调用前冻结，SHA256 为 `1d018c96b02f42e4e1a7aa783b1564c0c5621015cbe2ba2263a7e7bcc6d3b60c`。输入 manifest 为 `ad51ccd41f5e576167525a0ebfb85f9ee86b1f7f1d5cc73bc5f754228e1edd03`。监督脚本为 `e129566cb9938d6209db8c3c818a5531d32c7a36a56eb4c4958a38a1543d5e50`，外层测量脚本为 `fd46a3f8e0215f58e71b255896cd5743b710d40d7d7e794e90d8cc20bb09772a`。

| 模式 | 实际二进制 SHA256 | 原始结果 SHA256 |
|---|---|---|
| all-features | `086c1f1529bed2e51260ff0212224c7b110e15a8320f0bbd8d9650700439585b` | `7b92204511959f574a9c7705f38382c87b1f86f456e53c5cd6c65283ac1859e0` |
| no-default-features | `e3222da6c4f1d0267ec932581034602dfc27e03cb7a06f2cdaec4644e6784ff2` | `80b4d07adc14d3eefdb4375f4032cfc4d64f7c98275c185e1dd6857d3ca6cda6` |

## 实际执行结果

| 指标 | all-features | no-default-features |
|---|---:|---:|
| 最终状态 | PASS | PASS |
| 完整案例 | 39 | 39 |
| 生命周期 CLI 调用 | 105 | 105 |
| 常规完整案例 | 15 | 15 |
| 指定边界 SIGKILL 恢复案例 | 15 | 15 |
| 监督器死亡案例 | 1 | 1 |
| 无效输入及损坏恢复反例 | 8 | 8 |
| 持久化完整 policy DP | 93 | 93 |
| DP 开始而无完成记录 | 0 | 0 |
| 直接杀死 worker | 19 | 19 |
| 监督器死亡引发的 worker 死亡 | 1 | 1 |
| 被杀死的私有 Python 监督器 | 1 | 1 |
| 已回收全部本次后代 | 是 | 是 |
| 独立审计确认的成功 owner 操作 | 67 | 67 |

105 是生命周期 CLI 调用数。内部 canonical parser 是附加进程；按本次精确源码，每次成功 owner 操作恰好启动一次 parser，因此每种模式可从 67 个成功操作推导 67 次 parser 启动。这是源码与成功操作 receipt 的推导，不是独立枚举所有 parser PID。完整子进程费用已计入外层 RUSAGE，不得再把阶段 child CPU 加一次。

所有原模型文件保持不变。对于已发布的候选，恢复件是既有 owner 发布的不可变 `restore` artifact；下一任务读取该实际文件，验证完整字节及语义快照后执行新的全量 DP。对于尚未发布的 KEEP 分支，下一任务读取认证的原件。恢复调用不重新执行候选评价，也不会为缺失的结果制造接受证据。

两种模式的逐文件、完整旧字节、逆向字节、评价绑定、任务读回和费用完整性均通过另一 agent 的只读审计，审计材料为 `../value/native_execution_review.json`。审计过程没有再执行模型。

## 接受门确实会拒绝损坏保留能力的候选

下表来自 `all-features/cases/normal-*/TASK_00.json` 及保留任务的 `TASK_01.json`，保留六位小数用于展示。原始 JSON 保留完整精度。这里重执行的是以前暴露过的 teacher EditProgram 与任务，不构成新的样本外质量确认，也没有进行候选搜索。

| fit | 原模型 primary 价值 | 候选 primary 价值 | primary 增益 | 保留任务增益 | 带保留约束的决定 |
|---|---:|---:|---:|---:|---|
| 11 | 0.490934 | 0.548193 | +0.057258 | 0.000000 | 接受后恢复 |
| 23 | -0.007472 | 0.218314 | +0.225786 | -0.053876 | 拒绝后恢复 |
| 37 | 0.054526 | 0.088257 | +0.033731 | -0.060455 | 拒绝后恢复 |
| 53 | 0.195974 | 0.258105 | +0.062131 | -0.100127 | 拒绝后恢复 |
| 71 | 0.124536 | 0.239278 | +0.114742 | -0.224354 | 拒绝后恢复 |

五个只要求正 primary 增益的案例均接受后恢复；将最低增益设为 2 的五个对照均拒绝后恢复。加入真实保留任务、允许退化为 0 后，有四个候选被完整 evaluator 拒绝。它使用原模型与候选各自的完整前向、各自 occupancy、终端奖励、费用、continuation/terminal gap 和 PDI/概率质量检查，不依赖编辑方程自报质量。

五个模型的完整长度分别为 643760、643506、643928、643575、643795 字节，原件、候选、逆向恢复件均按完整长度处理。当前合法编辑域仍为原先授权的 196 个 joint readout 参数。补丁变化字节数不代表实际 owner 的完整模型读写、拷贝与哈希成本。

## 中断与拒绝覆盖

实际 SIGKILL 覆盖 15 个固定边界：`capture_complete`、`prepared`、`publish_intent`、`publish_effect`、`published`、`verify_intent`、`evaluation_started`、`baseline_complete`、`verify_effect`、`verified`、`accepted`、`restore_intent`、`restore_effect`、`restored`、`complete`。

其中 `capture_complete` 在持久捕获完毕、第一次 journal 之前停车，验证了尚无 owner 效果时的保守 KEEP。已发布而尚无完整接受证据的分支恢复原模型；第二次 recover 对记录和 journal 逐字节幂等。另有真实监督器死亡实验：监督器被 SIGKILL 后，worker 因 Linux parent-death signal 死亡，后续独立进程完成恢复与下一任务。

输入拒绝覆盖过期 request 哈希、与语义合同不一致的 primary task、过期 program snapshot、会阻塞普通 open 的 FIFO。恢复拒绝覆盖删除完整评价、篡改逐任务评价、删除实际逆向模型、篡改实际候选模型。这些案例没有伪造 `Complete` 或把错误当作接受。

这些是指定边界及给定损坏案例的资格。没有声称覆盖任意存储故障、断电、所有 parser 执行中点、所有初始化字节中点或跨二进制 journal 迁移。更早的部分捕获会保守拒绝，需要另一个身份明确的新 root；它不会被包装成同等于完整捕获后的自动恢复能力。

## 实测费用与预算口径

| 成本量 | all-features | no-default-features |
|---|---:|---:|
| 内层全部被回收子进程 CPU 秒 | 30.781734 | 29.867379 |
| 内层 campaign wall 秒 | 72.982249 | 65.285702 |
| 外层完整 campaign 进程树 CPU 秒 | 35.355987 | 33.865393 |
| 外层 wall 秒 | 73.366105 | 65.648576 |
| 外层所测子进程树峰值 RSS KiB | 28436 | 27944 |

每种模式冻结的预算是 180 子进程 CPU 秒和 900 wall 秒，两种模式均通过最终总量门。单个进程有内核 RLIMIT，监督器另做进程树实时采样、回收与最终总费用检查；采样不被称作内核整树硬配额。外层 69.221380 CPU 秒合计包括两个 campaign 及其被回收后代，不包括外层测量 wrapper 自身、CI 构建或其他分析进程。

阶段记录保留 `process_cpu_seconds` 与 `reaped_child_cpu_seconds`，另提供两者之和。认证编译、publish、完整评价、restore、next-task 可供 NDU 用明确的资源→效用系数换算。真实货币、使用次数和风险系数没有在本报告中臆定。阶段费用是外层费用的组成，不应相加成为新的“总成本”。

独立成本读核在每种模式识别出 77 份认证编译、25 份完整评价、34 份 publish、33 份 restore、31 份 next-task 阶段记录。process result 与持久评价文件重复出现的 15 份完整评价已逐一核对并去重。可分配阶段的进程树 CPU 合计为 24.852298 / 24.038362 秒；相对于内层全部子进程费用，仍有 5.929436 / 5.829017 秒保留为实测但尚未分配的成本，包括无最终 result 的 28 次 CLI、bootstrap、journal 和其他工作。没有将它们填为零。普通 accept 的完整生命周期平均为 0.501498 / 0.511856 CPU 秒；下一任务的外部费用另列。原始读核在 `../cost_ndu/COST_FACTS_REVIEW.json`。

## 原始失败与修正没有被覆盖

| 尝试 | 真实调用 | 原始结果 | 保留的外层 campaign 树 CPU 秒 |
|---|---:|---|---:|
| attempt001 | 0 | 本地不存在 `/usr/bin/time`，启动包装失败 | 未测，不填 0 |
| attempt002 / 3c167ba8 | 1 | 已认证来源 ID 被错误替换为本地路径，fail closed；owner 0，DP 0 | 0.258924 |
| attempt003 / 1a64a8d5 | 1 | 认证、两个保护哈希及编译通过，RuntimeConfig 空 hosts 被拒绝；owner 0，DP 0 | 0.395409 |
| attempt004 / 65ae015f | 210 | 双模式完整 PASS | 69.221380 |

前三次尝试、它们的源与二进制身份、stderr、原始捕获和费用继续保留。CI003、CI004、CI005 构建资格费用也有独立 `.time` 原件，不得因为后续成功而从总研究费用中删除。

最终窄修正没有修改全局授权规则或引入新 artifact owner：两个不同保护哈希域分别核验；compressed source ID 从已认证 receipt 按实际 SHA 与长度唯一定位；isolated owner 使用明确零远程能力的本地主机描述；worker 严格委托既有 parser 内部入口；parser 资源限额只能向下收紧；真实 parser 子进程进入阶段及外层费用账本。全局 root Cargo manifest/lock 保持不变。

## 公共入口边界

现有公共 `h_process_start` 可用显式 executable/argv 运行此原生子系统，无需新增专用 MCP 或修改并行 HIA rewrite。建议的两例、六次远端原生命令和期望文件在 `REMOTE_CLI_PLAN_65ae015f.json`：普通 run→recover→next-task，以及停车在 `published`、由本次公共 job timeout 终止后 recover→next-task。

这份本地报告不代替 pocket4 的实际公共入口回执。远端资格由 root 独立执行、保存并报告；本地完成不自动授予线上模型采用或现实任务全局最优编辑策略的结论。
