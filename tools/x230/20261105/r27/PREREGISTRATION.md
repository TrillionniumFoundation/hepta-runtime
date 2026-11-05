# R27 六主机验收预注册：R24 + borrowed serializer

## 决策与身份

R27 仅在已接受的 R24 源码上应用 borrowed observation serializer 补丁。修改 `src/mcp/runtime/ssh.rs`，新增同目录的 serializer 回归测试；其余编译输入保持 R24。正式基线 A 为 R24，源码提交 `baab4def80be7af015b2e7a594cb302f66c4130e`，运行时 SHA-256 为 `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13`。B 必须来自实际完成资格的 R27。

本文在任何 R27 实测之前固定协议与门槛。全部 R27 资格结果、原 job ID、最终 source-map 和二进制哈希仍未产生，模板保留 null。代码资格由另一个任务准备：根目录为 `/home/qian/hepta-runtime-optimization-20261105-b96-r27`，源码、target 和资格输出分别为其 `source`、`target-build`、`qualification-01`。这一准备没有执行远程命令、Rust 编译、上传或 Git 变更。

资格必须完成原有八阶段：format、fmt-check、harness-tests、clippy、test-build、isolated-tests、audit-isolated-tests、release；必须保留原 native terminal、完整日志、实际格式化后的源文件图、三个实际保留二进制和完整测试审计。预期 221 个编译输入、原 19 个 harness 文件不变；全部 1652 个非忽略测试通过，34 个忽略，1686 个选中，失败与重试均为 0。rustfmt 仅允许修改这两个候选文件。实际结果不能由模板推断。

## 固定性能门槛

使用已接受 R24 的原门槛，整轮数据全部进入原聚合公式：

| 指标 | 固定通过条件 |
| --- | --- |
| C1、C8、C16 各档成功吞吐 | B/A ≥ 0.95 |
| C1、C8、C16 各档 RPC p95 | B/A ≤ 1.10 |
| C8 成功吞吐 | B/A ≥ 1.03 |
| C8 controller CPU / 成功调用 | B/A ≤ 0.97 |
| 原测量与重启 controller 的采样 RSS 最大值 | B ≤ min(A + 512 KiB, A × 1.05) |

其他档的 CPU、全部子进程成本、各物理主机结果和相邻 ABBA 配对都完整报告。相邻配对只作诊断，不能替代整轮聚合。资源字段缺失保持为缺失，不补成 0。门槛不会因为候选只有小幅收益而调整；不足 3% 的收益按本轮协议拒绝。组件 CPU/分配减少可单独报告，但不能替代端到端通过。

## 七阶段协议与调用预算

真实六主机集合为 `ai395`、`mac`、`main`、`pocket4`、`rog`、`x230`，沿用原物理拓扑、profile、原始六份冻结 job 记录和 R16 工具 SHA。两个 Tokio worker，`MALLOC_ARENA_MAX=1`；ABBA 次序和并发档均不改变。

| 阶段 | 固定内容 | 已有单阶段上限 |
| --- | --- | ---: |
| 1. native-observation | R24/R27 ABBA；每 round 按 C1/C8/C16，每 cell 192 次计量 + 24 次 warmup | 1800 s |
| 2. native-audit | 原独立观察审计，验证原数据、六机拓扑、重启和资源证据 | 180 s |
| 3. native-boundary | 候选两次 C32 burst，沿用成功/容量拒绝分类及 drain/recovery | 600 s |
| 4. boundary-audit | 原独立容量/边界审计 | 180 s |
| 5. cancel-recovery | 候选单次六机 C6 canary，保留 ROG 私有 master 中断、controller crash/restart、same-key、cancel 和终态输出证明 | 600 s |
| 6. recovery-audit | 原独立恢复与取消审计 | 180 s |
| 7. campaign-summary | 原 R24 效率门与全部正确性结果，加原始计数器的子进程成本复算 | 180 s |

Native 固定为 2304 次计量、288 次 warmup、72 次 preflight/restart，共 2664 次只读调用，失败为 0。边界阶段固定 64 次 C32 尝试、202 次总工具调用；容量拒绝单独计数，不算成功吞吐，不要求凑出某个拒绝次数。C6 canary 固定六个新 job、12 次 same-key lookup、12 次取消；状态/输出与独立 SSH 证明仍由原有限协议控制。

R27 没有 R25 的取消 reserve 改动，因此不继承该机制专用的 saturation gate、24-admitted/9-active 上限或额外 lifecycle ABBA。上述单次原 canary 是 R24 完整验收既有部分。运行时 global/host/admission/capture 等容量不调整，不扫描其他参数。

## 资源成本与归因

完整保留原始 `/proc/<pid>/stat` 前后计数器及 PID/birth 绑定，分别复算 controller 的 `utime/stime`、已等待并回收子进程的 `cutime/cstime`，以及二者合计的 CPU/调用与 CPU/wall。每档 A/B 的完整原 cell 都参与汇总。子进程 CPU 在 reap 时记账，不能把 cell 边界解释成它的精确全生命周期。

原 100 ms trace 和独立分析继续报告 controller、SSH descendants、其他/未知 descendants 的 CPU 样本，RSS/HWM、FD、线程、controller tree、可用样本数和全部采样错误。已回收子进程 CPU 与 sampled SSH CPU 分栏报告，不相加；仍存活 master 的 CPU 也不能无条件当成互斥部分追加。RSS 是非同时、可能重复计算共享页面的采样值。Python harness、远端 helper 和全群 CPU 不在这些原计数器内，不能把 controller 减少冒充全群精确节省。

成本复算只读取本轮已有证据，不增加工作负载或另一套性能阈值。复算失败使证据不完整；原固定性能门原样保留。

## 干扰、原始证据和失败处理

采用已评审 revision 02 compiler monitor：1 Hz 从前置校验、90 s quiescence，覆盖全部阶段至原 cleanup 和最终源检查完成。采样必须实际完成并独立验证；不得用起跑前一次检查替代。现有 lateness/gap/scan/CPU/ledger 上限原样保留；该采样仍不能证明两个样本之间绝无编译活动。

总 campaign 保留 3300 s、Mac held-agent envelope 3600 s，并为 cleanup 预留 160 s。原 Child 的 PID/birth/process-group 保管、等待回收、SIGINT 120 s 再有界 SIGTERM/SIGKILL 的次序不改。监视器失败保留原性能结果，但禁止性能归因和采纳。

根代理统一安排独占测量窗口。另一个会话独占其正在推进的 R26/diagnostic05；本任务不查询或操作它们。R27 运行前必须确保没有会重叠的编译、打包或其他压测。测量与输出只使用新的 b96/R27 路径；不得覆盖旧目录。

只执行一次冻结 attempt。完整保留原 holder、stdout/stderr、terminal DTO、原始调用、资源 traces、监视 ledger、所有审计和失败状态。未知 effect 按原 job/key 对账，不重放，不换 key，不选择“好样本”，不丢掉某个 round，不自动重试。完成但未通过性能门是有效拒绝结果，继续保留已接受 R24。
