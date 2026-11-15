# X230 R22：采用 SSH 完整读取的有界参考比较

**采用 R22。** 六机 release observation 的 C8 成功吞吐由 **23.3555 提高至 44.4223 calls/s（+90.20%）**，controller CPU/call 由 **72.5781 降至 28.3333 ms（−60.96%）**，p95 由 **420.901 降至 238.481 ms（−43.34%）**。C1/C8/C16 均通过冻结门槛。代价是最大采样 controller RSS 从 **17,796 增至 18,584 KiB，增加 788 KiB（+4.43%）**，在预先约定的预算内。

完整资格、容量、取消/恢复均通过；本轮采用的是源码优化，记录中 `production_services_modified=false`。这是一轮有限六机 campaign 的实测结果，不声明全局最大吞吐或统计显著性。

## 对象、源码与行为

基线为 `e85f869e48e643a3e94cb7220d27181ad82c8562`，其运行时源码保持已接受的 R19。[R20/R21 拒绝结论](X230_OPTIMIZATION_20261105_R21.md) 保留。R22 不包含被拒绝的延后 Python 导入候选，也不包含后续 R23 的 shell/false 参考扩展。

生产变化仅在 `src/mcp/runtime/ssh_observation_profile.rs`，新增相邻 `ssh_observation_reference_tests.rs`。固定 `/usr/bin/ssh` 启动时仍完整读取并通过预置 SHA256 pin；文件不超过 2 MiB 时，将已验证字节保留为私有、共享的 `Arc<[u8]>`。后续每次完整 fresh read 与参考逐字节比较。超限 SSH 文件和其余五项输入保留 SHA256。

读到不同字节后仍继续读取，保留所有取消检查点、读取错误、长度限制、描述符/路径复查和最终内容判定顺序。成功 warm observation 的原有 12 轮 pin-set 验证、合计 72 次完整文件读取，以及 worker/owner 和 await 两侧的验证均保留。克隆 pin 共享参考字节。

启动信任仍来自 SHA256 pin；后续精确相等缩小内容接受集合，不构成文件系统原子快照。2 MiB 是每 Profile 参考字节体上限，不含分配器开销、转换瞬时峰值或多个 Profile；进程 RSS 单独测量。

## 完整资格与源码绑定

八个阶段 `format / fmt-check / harness-tests / clippy / test-build / isolated-tests / audit-isolated-tests / release` 均退出 0。五个测试目标共 **1,678 selected、1,644 passed、0 failed、34 ignored、0 retries**，隔离测试耗时约 248.067 秒，原始测试审计 `errors=[]`。新增七个功能测试及一个默认 ignored 的机制基准均列入实际清单。

实际资格源码映射包含 220 项输入，构建前后相同。独立审查直接读取基线 Git root/src/examples 树，逐一重哈希本地完整文件：215 个基线 src 叶文件对应 216 个候选叶文件，仅 profile 文件修改和 reference 测试新增；Cargo.toml、Cargo.lock、rustfmt.toml 与 examples 保持相同。全部 220 项与实际 X230 qualification map 逐项相等；campaign 的带大小输入映射也重新计算相符。候选 src tree 为 `e0f8f7a8856c1ae4385a52aafa7d22204f19c435`。

| 产物 | A 字节数 | B 字节数 | 身份结果 |
|---|---:|---:|---|
| hepta-runtime | 14,369,848 | 14,371,784 | B SHA256 `346b57590211e62ce8732dfcea703c2fae4b2dca5fd62f870c1abd34b1158d20` |
| hepta-runtime-jobctl | 739,016 | 739,016 | 两臂 SHA256 相同：`61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62` |
| native_process_driver | 2,896,456 | 2,896,456 | 两臂 SHA256 相同：`51165c1e38409248f5fdb7da2036ebe5e05eec7576035e95bd4b8e2a5c675530` |

本轮复用未修改的依赖缓存，重编根 crate；不沿用历史 R19 的全空 target 构建声明。以上 ELF 身份来自实际远端资格和 campaign 记录，不声称本地持有并重哈希了 ELF 实体。

## 完整文件校验机制 ABBA

机制 runner 绑定成功资格、源文件及保留的实际测试产物，枚举五个目标，只执行唯一的 exact ignored case。实际 SSH 文件为 **846,888 B**，SHA256 为 `fc47ea24323fdd5687c5aefae6fd0060faabfa8f2944c6a68f6a442fbe0dd131`。三块 ABBA、12 个计时 cell、每 cell 128 次，共 **1,536 次计时完整校验**；每个 arm 另有 8 次预热。

| 指标 | SHA arm | Reference arm | B/A |
|---|---:|---:|---:|
| wall ms / verification | 2.888466 | 0.181885 | 0.062969 |
| thread CPU ms / verification | 2.888286 | 0.181817 | 0.062950 |
| process CPU ms / verification | 2.888306 | 0.181836 | 0.062956 |

Thread CPU/call 下降 **93.7050%**。这里使用资格保留的 dev opt-level=1 libtest，两种 pin 同时驻留同一进程，因此只解释完整校验 CPU/wall；release RPC 收益由下一节独立测量，机制基准不用于 A/B RSS 结论。

## 六机 release observation ABBA

负载为已完成作业的 `process_status` / `process_read` 观测 RPC；这里的 calls/s 不是新作业启动吞吐，也不是集群计算吞吐。

实际 campaign 为 2026-11-05 04:06:00–04:12:28 UTC，预先冻结六个物理机器分组。使用 workers=2、MALLOC_ARENA_MAX=1，C1/C8/C16 各按 ABBA 执行，每 cell 192 measured + 24 warmup。实际为 **2,304 measured + 288 warmup + 72 preflight/restart = 2,664 tool calls，0 failed**，原始 native 审计核对 2,672 个 RPC frames。

| 并发 | A 成功 calls/s | B 成功 calls/s | 吞吐变化 | Controller CPU ms/call：A → B | CPU 变化 |
|---|---:|---:|---:|---:|---:|
| C1 | 4.2101 | 6.6148 | +57.12% | 130.5729 → 47.3698 | -63.72% |
| C8 | 23.3555 | 44.4223 | +90.20% | 72.5781 → 28.3333 | -60.96% |
| C16 | 23.5428 | 46.0055 | +95.41% | 72.8385 → 28.6458 | -60.67% |

| 并发 | p50 ms：A → B | p95 ms：A → B | p95 变化 | p99 ms：A → B | p99 变化 |
|---|---:|---:|---:|---:|---:|
| C1 | 231.943 → 144.369 | 294.390 → 204.788 | -30.44% | 338.656 → 241.861 | -28.58% |
| C8 | 331.625 → 172.793 | 420.901 → 238.481 | -43.34% | 476.329 → 286.499 | -39.85% |
| C16 | 672.187 → 334.530 | 782.730 → 394.901 | -49.55% | 836.627 → 421.247 | -49.65% |

以上采用原分析器的汇总口径。Controller CPU 是同一 controller 的同步 CPU 差值/计时调用数，不包含 Python harness 或远端进程。两组相邻 C8 配对的吞吐 B/A 分别为 1.9669、1.8407，CPU/call B/A 分别为 0.3839、0.3970，方向一致；它们是有限样本诊断，不是置信区间。

冻结门为所有档位 throughput B/A ≥ 0.95、p95 B/A ≤ 1.10，C8 另要求 throughput ≥ 1.10、controller CPU/call ≤ 0.90。全部通过，未重试性能以选择结果。最终 report 的 `passed`、`adoption_passed`、`inputs_unchanged`、`source_inputs_unchanged` 均为 true，七个 campaign 阶段退出 0。

## 内存、容量及恢复

RSS 每 0.1 秒采样，取每个 arm 两个 measurement controller 与两个 restart controller 中的最大可用值。A=17,796 KiB、B=18,584 KiB，增量 788 KiB、比值 1.04428；冻结上限为 min(A+2,048 KiB, A×1.15)=19,844 KiB，因此通过。

这项变化增加常驻参考字节，不能称为内存下降。它是 controller 的采样峰值，不是精确生命周期峰值、整个集群内存或 2 MiB 的进程硬上限。原始 FD/后代进程采样中的 PermissionError、进程退出及缺测均保留，不推导未经验证的 FD 或整棵进程树内存改善。

C32 两次 burst 各 **16 success + 16 精确 capacity rejection + 0 other error**；96 个 post-drain calls、drain/recovery/restart 均通过。完整 boundary 为 202 tool calls、204 个已核对 RPC frames。容量拒绝单列，不计入成功吞吐。32 是客户端 pending 峰值，内部 admission 峰值没有遥测；本轮 16/16 分布不证明固定的最大成功并发。

C6 正确性 canary 完成 **90 native calls、36 次独立 SSH 检查、6 个新作业、12 次 same-key lookup、12 次 cancel**，实际 ROG 私有 transport 中断、controller crash/restart 及恢复审计通过。这不是 lifecycle ABBA 性能比较。原脚本路径约束使本轮 raw 位于 R16 下新的 `r22-cancel-recovery-01`，在 R22 归档中保留准确来源映射。

## 证据与取舍

源码审查及完整文件身份见 [R22 证据索引](../tools/x230/20261105/r22/README.md)、[实际资格与 Git 源码绑定](../tools/x230/20261105/r22/reviews/qualified-source-binding-01.json) 和 [正式 campaign 汇总](../tools/x230/20261105/r22/reviews/campaign-summary-01.json)。源码与结果已由 `afec5354d1e0` 发布；伴随取证提交补齐三份完整原始包与下载链接。92 个固定版本分片及 7,695 个 payload 文件的字节和 SHA256 均核对通过；省略的 ELF/私有配置仍只保留实际远端身份，没有在本地重新哈希其实体。本轮 qualification map 摘要为 `c998ca803237d1feb8f6ef925bc861171b70969e61602c126ceade8d1acf09b6`；campaign 的大小+SHA256 输入映射摘要为 `a9828a44ef0d8922e6a91dd8a71dadb172a07a4b4156fafab2831aa8b5f889bc`。两种映射编码不同，不能互换。最终 campaign report 原始字节 SHA256 为 `3ec6494b2dc9dd25dbe3650f7becd174b6891aabdc35a4f9f89d16082acfedf7`。

第一次证据导出因保留的 libtest 为 540,751,056 B、超过导出器初版 256 MiB 读取上限而在首包前退出；这是取证工具边界，不是资格或性能失败。02 只将流式读取上限提高至 1 GiB 并补齐稳定性/配置排除检查，ELF 仍只留身份、不打包实体；原失败报告和原代码保留，测量未重跑。

采用 R22 的依据是 C8 明确的端到端吞吐/CPU改善、所有回退与资源门通过，以及完整资格和恢复验证。继续使用 workers=2、arena1、常态 C8；C16 本轮吞吐略高但尾延迟也更高，按实际并发需求选择。任何后续候选都应以已接受的 R22 实际源码/产物为基线单独验证。
