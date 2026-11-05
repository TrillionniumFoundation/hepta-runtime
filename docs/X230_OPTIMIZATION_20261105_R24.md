# X230 R24：公共可执行文件字节校验与终止 master 的提交前续建

## 当前状态

**R24 完整资格与正式六机验收全部通过，已满足本轮既定采用门槛。** 相对本轮实际 R22 A，C8 吞吐提高 **18.67%**、controller CPU/call 降低 **31.49%**，C16 吞吐提高 **20.59%**。完整 campaign 控制报告已闭合全部阶段、回收与输入不变性；最终 GitHub 提交身份由发布后的精确 readback 记录确认。正式比较基线是已采纳的 [R22 源码提交 `afec5354`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/afec5354d1e0eca09f10ccabd73a01be2f14092c)。[R23](X230_OPTIMIZATION_20261105_R23.md) 的原失败结果保留，不作为已采纳版本或重跑成功处理。结果依据：[本轮正式摘要](../tools/x230/20261105/r24/reviews/campaign-summary-01.json)。

R24 组合两项改动：将 R22 的公共 SSH 字节基准扩展到固定 `false` 和 shell；对已经明确终止、但维护任务尚未关闭接纳的原 SSH master，在创建 slave 之前进入现有续建路径。完整的源码绑定及资格证据见 [本轮证据索引](../tools/x230/20261105/r24/README.md)。

## 源码变化与边界

### 共享 2 MiB 的公共文件字节基准

每个 profile 使用同一个 2 MiB payload 预算，按原有加载顺序 SSH → `false` → 固定 shell 分配。每份基准都在原来的完整读取、文件身份检查和启动 SHA-256 pin 校验成功后才安装；超出剩余预算的文件继续使用原 SHA 路径，且不消耗预算。基准通过私有不可变 `Arc<[u8]>` 共享，clone 不复制整份 payload。

本轮延续 [R23 记录的公共文件集合](X230_OPTIMIZATION_20261105_R23.md)：三个公共文件共 1,003,608 字节，比 R22 的 SSH 基准多 156,720 字节。2 MiB 是每 profile 的基准 payload 上限，进程 RSS 仍由正式观测结果单独验收。profile 正文、SSH 配置与 known_hosts 仍走原来的 SHA 校验。具体改动及实际输入身份见 [源码绑定](../tools/x230/20261105/r24/reviews/qualified-source-binding-01.json)。

热路径仍完整重新读取文件，再将当前读取的数据与启动时已验证的基准逐字节比较。内容不符不会提前结束读取；原有短读、超长、文件 stamp、取消、owner 和 await 后接受检查继续执行。常规成功观测中的原有 72 次完整读取没有删除；续建时仍按原流程重新执行必要校验。

### 已知终止 master 在 slave 之前续建

R23 的原始取消恢复检查，在确认 ROG 私有 master 的 pidfd 已终止后，下一次 `process_status` 收到 `observation SSH child exited`。R22 与 R23 的 pool 源码相同：旧路径先凭 `accepting` 和剩余 AGE 选中 master，离开接纳循环后才检查原 Child 是否存活。异步维护任务尚未关闭旧 generation 时，这条请求会直接失败。该证据定位了一条已有时序窗口，不证明 reference 改动创造了该问题。

R24 将同一次 `child.lock → try_wait → process identity` 检查的结果明确区分为 `Live` 和 `Terminal`。只有原 Child 的 `try_wait` 给出终态、且当前请求尚未创建 slave 时，才释放当前 `ActiveMaster`、host permit 和 global permit，并进入现有按 generation 合并的续建流程。多个等待者沿用同一个 host semaphore 和同一份原 retirement receipt。

启动新 master 时仍使用严格 `verify_live` 包装：启动中的 Child 退出仍直接失败。I/O、身份、proc、socket、peer 错误继续失败；代码没有按错误字符串猜测可重试性，也没有在其它错误后追加一次 terminal probe 来改判。已经提交给 `captured()` 的命令不会重放。master 在存活检查之后再次退出，仍可能产生后续传输错误；本改动不承诺任意断线自动恢复。[独立静态审查](../tools/x230/20261105/r24/reviews/source-review-01.json) 核对了这些边界。

### 确定性回归用例

新增 `renew-terminal` 场景复用原有隔离测试框架：原 Child 已被回收，`accepting=true`，master 还有 60 秒 AGE，而请求期限为 15 秒；测试不运行 maintenance。一个受控 active 计数暂时阻止新 master 启动，使测试能检查唯一下一 generation、原 host semaphore、global 容量归还、当前请求 active 计数释放、等待中的取消返回，以及原来的清理路径。原 `renew-deadline` 用例继续保留，并共享加强后的断言。

该场景验证提交前的续建和取消路径；真实六机的 master 中断、作业存活、取消和重启仍由独立 correctness gate 验收。[资格与格式审查](../tools/x230/20261105/r24/reviews/qualification-review-01.json) 记录了测试范围。

## 实际资格结果

2026-11-05 的完整资格报告为 `qualified=true`。format、fmt-check、harness-tests、Clippy、test-build、isolated-tests、audit-isolated-tests、release 共八个阶段均返回 0。五个测试目标共选中 1,679 项：**1,645 通过、0 失败、34 忽略、0 重试**。测试摘要的 inventory 总数和 ignored 名称数量均已交叉核对。证据：[完整报告](../tools/x230/20261105/r24/reviews/qualification-report-01.json)、[测试摘要](../tools/x230/20261105/r24/reviews/isolated-tests-summary-01.json)、[资格闭合](../tools/x230/20261105/r24/reviews/qualification-closure-01.json)。

完整报告为 83,365 字节，SHA-256：

```text
bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971
```

报告通过固定 version 的两个分片读回，逐片及合并后的完整 SHA-256 均重新核对。`source_input` 对应冻结的格式化前候选；format 只将测试中的一条 `assert_eq!` 展开为多行。生产文件与独立审查时的候选逐字相同。格式化后的 `source_tested` 和 `source_after` 全部 220 项一致，也与完整本地输入重新计算的 SHA-256 一致。[格式差分](../tools/x230/20261105/r24/reviews/pool-tests-format-01.diff) 保留了唯一的格式变化。

| 实际 B 产物 | 字节数 | SHA-256 |
|---|---:|---|
| `hepta-runtime` | 14,373,416 | `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13` |
| `hepta-runtime-jobctl` | 739,016 | `61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62` |
| `native_process_driver` | 2,896,456 | `51165c1e38409248f5fdb7da2036ebe5e05eec7576035e95bd4b8e2a5c675530` |

上述三个文件的实际完整 SHA-256 和大小另经远端只读文件身份接口核对，与完整资格报告、实际 campaign inputs 和 compact 摘要一致；未下载 ELF 正文。jobctl 和 driver 与 R22 相同。[产物身份记录](../tools/x230/20261105/r24/reviews/qualification-output-identities-01.json) 保存了精确来源。

## Git 与编译输入绑定

实际候选相对 R22 恰好修改五个源码文件：三个 reference 实现/测试文件，以及 pool 实现和测试。Cargo.toml、Cargo.lock、rustfmt.toml 与 examples 不变，无源码新增、删除或 executable mode 变化。已对 R22 全部 220 个完整叶文件重新计算 Git blob，并核对实际 Git 树；候选的全部 220 项也重新读取、计算并与真实资格输入比较。

| 绑定项 | 值 |
|---|---|
| R22 基线 `src` 树 | `e0f8f7a8856c1ae4385a52aafa7d22204f19c435` |
| 实际候选 `src` 树，本地按 Git 对象格式重构 | `b71cac25e2c2138837f27f3c74f6a2dc5c56b565` |
| 220 项 SHA-256 map 摘要 | `c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd` |
| 220 项大小与 SHA-256 map 摘要 | `e449e138216242c89b2ceff69babafe658411a42c73df0c66b222899540bdff7` |

两种 map 的字段结构不同，因此摘要不同；它们绑定同一组实际文件。资格前记录原样保留，资格闭合另有完整报告及输出身份依据。[源码绑定](../tools/x230/20261105/r24/reviews/qualified-source-binding-01.json) 明确区分源码、资格、campaign 和发布范围。

## 冻结的正式六机验收

性能负载为六机上已完成作业的 `process_status` / `process_read` 观测 RPC，不代表新作业启动吞吐或集群计算吞吐。固定 workers=2、allocator arena=1，C1/C8/C16 按 ABBA 比较实际 R22 A 与 R24 B；计划包含 2,304 次计量调用、288 次 warmup 和 72 次预检/重启调用。测量方案及实际二进制输入分别见 [冻结计划](../tools/x230/20261105/r24/measurement-plan-01.json) 和 [实际 inputs](../tools/x230/20261105/r24/campaign-inputs-01.json)。

| 门槛 | 冻结要求 |
|---|---|
| 每个 C1/C8/C16 档 | B/A 吞吐 ≥ 0.95；p95 ≤ 1.10 |
| 主要 C8 档 | B/A 吞吐 ≥ 1.03；controller CPU/call ≤ 0.97 |
| controller RSS | B ≤ `min(A + 512 KiB, A × 1.05)` |
| C32 容量边界 | 两次固定 burst，由原审计器检查；其它错误必须为 0 |
| C6 取消恢复 | 六个新 fixture、ROG 私有 master 中断、原作业恢复、同 key 查找与取消/重启，必须通过原审计器 |

RSS 取每臂两次测量 controller 和两次重启 controller 中采样到的最大值；它不是 payload 上限或集群内存上限。取消恢复是 correctness canary，不作 lifecycle ABBA 吞吐声明。观测池既有 16 个逻辑接纳、8 个全局会话、每 host 2 个会话和 8 个 master 上限保持不变。

## 正式六机结果

实际完成 **2,304 次计量调用 + 288 次 warmup + 72 次预检/重启调用 = 2,664 次调用，0 失败**。吞吐按每臂两个计量区间的总成功调用数除以总 elapsed 计算；CPU/call 使用同一 controller 的同步 CPU 增量，排除 Python harness、远端进程和 warmup。下列比率和门槛已经从 [native 独立分析](../tools/x230/20261105/r24/reviews/native-analysis-01.json) 的计数重新计算，与原摘要一致；百分位来自原始证据审计器，未用历史轮次合并结果。[独立算术复核](../tools/x230/20261105/r24/reviews/campaign-arithmetic-review-01.json) 保存了计算范围。

| 并发 | R22 A 吞吐，次/秒 | R24 B 吞吐，次/秒 | 吞吐变化 | controller CPU，A → B 毫秒/调用 | CPU 变化 |
|---|---:|---:|---:|---:|---:|
| C1 | 6.664 | 7.458 | +11.91% | 47.786 → 31.458 | −34.17% |
| C8 | 45.611 | 54.126 | +18.67% | 28.203 → 19.323 | −31.49% |
| C16 | 45.844 | 55.285 | +20.59% | 28.984 → 19.661 | −32.17% |

| 并发 | p95，A → B 毫秒 | p95 变化 | p99，A → B 毫秒 | p99 变化 |
|---|---:|---:|---:|---:|
| C1 | 201.891 → 185.579 | −8.08% | 250.096 → 221.385 | −11.48% |
| C8 | 221.493 → 186.892 | −15.62% | 253.317 → 215.211 | −15.04% |
| C16 | 411.531 → 342.554 | −16.76% | 450.331 → 369.900 | −17.86% |

### 内存与容量

按冻结口径，R22 A 的最大采样 controller RSS 为 **18,528 KiB**，R24 B 为 **18,488 KiB**，采样差值 **−40 KiB**；B 低于 `min(18,528 + 512, 18,528 × 1.05) = 19,040 KiB`，RSS 门通过。候选实际增加了 156,720 字节 reference payload，因此这个小采样差值不能证明固有分配量降低，也不能作为总集群内存结论。FD/进程采样中的缺失与退出竞争记录仍保留，未被改写成精确完整资源观测。[RSS 原行及门槛](../tools/x230/20261105/r24/reviews/campaign-summary-01.json)。

C32 的两次 32-attempt burst 共 **32 成功、32 容量拒绝、0 其它错误**；每次实际为 16 成功与 16 容量拒绝，排空后 96 次计划内探测通过。含 warmup 与预检/重启共 202 次工具调用。容量拒绝独立计数，不进入成功吞吐；32 个 client attempts 不代表 32 个内部已接纳身份。[容量独立分析](../tools/x230/20261105/r24/reviews/boundary-analysis-01.json)。

### 取消、恢复和收口

C6 correctness 摘要确认 **90 次 native 调用、36 次独立 SSH 检查、6 个新 fixture、12 次同 key 查找、12 次取消**；ROG 私有 master 中断、原 controller crash/restart、原作业及终态恢复检查均通过原审计器。此处是固定 correctness canary，不是 lifecycle ABBA 吞吐结论。[独立 lifecycle 验证](../tools/x230/20261105/r24/reviews/lifecycle-analysis-01.json)。

Mac holder 报告 `passed=true`、远端 returncode=0；本轮持有的 agent 已回收，socket 和私有目录在上下文退出后不存在。未进行自动 SSH 重试或服务修改。[holder 原报告](../tools/x230/20261105/r24/reviews/mac-holder-01.json)。

## 采纳与发布依据

独立摘要中的 `performance_gates_passed`、`correctness_verified`、`adoption_gate_passed` 均为 true，拒绝原因列表为空。完整 [campaign 控制报告](../tools/x230/20261105/r24/reviews/campaign-control-01.json) 的七个阶段均返回 0，全部 `waited_and_reaped`、owned process absent 和 process-group absent 为 true；`passed`、`adoption_passed`、`inputs_unchanged`、`source_inputs_unchanged` 和 `baseline_source_inputs_unchanged` 均为 true。A、B 两侧各 220 项完整本地输入重新计算的大小与 SHA-256 摘要也分别等于实际控制报告，且实际 A/B 二进制身份与对应资格一致。

本轮 campaign 从 `2026-11-05T05:41:43.570198Z` 至 `05:46:56.804535Z` 完成。完整控制报告为 **100,033 字节**，SHA-256：

```text
066952f12414e8f7291e21e58a77d53d4cd712104557bd6bdfdd7c383f9f1e2a
```

[独立算术与最终闭合复核](../tools/x230/20261105/r24/reviews/campaign-arithmetic-review-01.json) 同时核对了独立 lifecycle 报告、ROG 原 master 的终态与替代 generation、六个作业各执行一次及重启后终态字节不变。GitHub 源码发布仍由独立的 commit/ref/readback 记录证明。本轮是一次有限六机 campaign，不附加统计置信度或跨历史轮次的累计收益声明，也不改变 R23 的原失败事实。

## 证据归档状态

核心提交包含资格、源码绑定、审查、实际 inputs、冻结工具、完整 campaign 控制报告及各项独立分析原字节。完整原始日志包由同一 R24 版本的伴随取证提交补齐；下载链接在实际入库后加入证据索引。

原始取消恢复证据按未修改的 harness 约束保存在 `/home/qian/hepta-runtime-optimization-20261104-r16/r24-cancel-recovery-01`，由本轮控制报告明确绑定。这是本次 R24 的新目录，不覆盖 R23 原失败证据。
