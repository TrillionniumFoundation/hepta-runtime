# X230 reference buffer 最终筛选：保留 16 KiB

## 决定与实测

本轮最后一个 16→64 KiB reference buffer 候选**未采用**。完整三公共文件校验的平均线程 CPU 仅降低 **5.672%**，未达到事先冻结的 **至少降低 20%** 门槛；`false` 单文件校验 CPU 增加 **2.739%**，超过允许的 **2%** 回退。已发布的 R24 保持 **16 KiB**，本轮不再扩展 buffer 参数或重复测量这个候选。这是当前机器、实现和冻结工作负载下的停止依据，不证明所有实现或环境已达到全局最优。[实际摘要](../tools/x230/20261105/reference-buffer/evidence/attempt-02/summary.json)、[独立算术与回执审查](../tools/x230/20261105/reference-buffer/reviews/arithmetic-receipts-01.json)、[R24 发布读回](../tools/x230/20261105/reference-buffer/reviews/r24-accepted-publication-readback.json)。

下表是单进程组件每次完整校验的平均 **thread CPU**，单位 µs；A 为 16 KiB，B 为 64 KiB。`public_triplet` 一次执行 SSH、false、固定 shell 三文件的完整读取及对应外层检查。它单独计时，不以三个单文件均值相加代替。

| 场景 | A：16 KiB，µs | B：64 KiB，µs | B/A | CPU 变化 | 冻结门槛与结论 |
| --- | ---: | ---: | ---: | ---: | --- |
| `/usr/bin/ssh` | 179.393606 | 157.726865 | 0.879222 | −12.0778% | 诊断项，不单独决定采用 |
| `/usr/bin/false` | 36.747514 | 37.754157 | 1.027394 | +2.7394% | ≤1.02：**失败** |
| `/usr/bin/dash`，固定 shell 解析目标 | 98.347646 | 97.119801 | 0.987515 | −1.2485% | ≤1.02：通过 |
| 完整 `public_triplet` | 328.638698 | 309.998305 | 0.943280 | −5.6720% | ≤0.80：**失败** |

每个场景、每个 arm 有 6 个计时 cell，共 1,536 次完整校验；全部 48 个 cell 都纳入计算。原始记录是 1 条 setup、48 条 sample、1 条 complete，共 50 条，文件 16,046 B。独立审查直接从每条记录的整数时钟差累计，用有理数重算比值和门槛，没有调用原 summarizer，也没有重新运行负载。[完整原始 JSONL](../tools/x230/20261105/reference-buffer/evidence/attempt-02/run.stdout)、[逐 cell 整数算术及汇总](../tools/x230/20261105/reference-buffer/reviews/arithmetic-receipts-01.json)。

各 ABBA 块的线程 CPU 比值也全部保留；有限样本不被描述为置信区间：

| 场景 | 块 1 B/A | 块 2 B/A | 块 3 B/A |
| --- | ---: | ---: | ---: |
| SSH | 0.866520 | 0.884119 | 0.887266 |
| false | 1.032525 | 1.007683 | 1.042099 |
| shell | 0.983284 | 0.988728 | 0.990548 |
| public triplet | 0.968851 | 0.933084 | 0.927995 |

wall time、process CPU、每块数据和单文件按相同频率相加的诊断比值均保留在摘要中；后者为 0.930402，未替代主指标，也没有据此放宽门槛。[实际摘要](../tools/x230/20261105/reference-buffer/evidence/attempt-02/summary.json)。

## 为什么只做这个有限筛选

R22 将 SSH 的重复 SHA 校验替换为完整新读取与私有不可变参考字节比较；R23 准备的同一方法扩展到共享 2 MiB 预算下的 false/shell，最终随 R24 的终止 master admission 修复一起通过完整验收并发布。算法变化使旧 SHA 路径上的 buffer 结果不足以直接判断新的 reference 路径。本筛选只检查新的公开文件读取组件，不重新测试或改变 R24 pool。[已发布 R24](https://github.com/TrillionniumFoundation/hepta-runtime/commit/baab4def80be7af015b2e7a594cb302f66c4130e)、[执行绑定说明原件](../tools/x230/20261105/reference-buffer/evidence/execution-binding-note.json)。

组件从实际资格通过的 R23 source 提取，完整 220 项输入映射与资格报告的 `source_tested`、`source_after` 一致。使用的 profile、validation 与 reference tests 三个源文件，在已采用 R24 中逐字相同。两个隔离 Rust module 的唯一区别是 `VERIFY_BUFFER_BYTES` 的 16/64 KiB 常量；PinnedFile/helpers、完整 fresh read、stamps、固定 shell 解析、公共文件加载与预算顺序均按原文保留。guard 使用真实 CancellationToken 与 Tokio Instant，`check_current` 方法体按原文提取，只有供它使用的薄字段结构；没有模拟新的 worker、admission、permit 或 owner 生命周期。[原始 arm diff](../tools/x230/20261105/reference-buffer/evidence/prepared/arm-diff.txt)、[实际修正组件](../tools/x230/20261105/reference-buffer/evidence/tooling-fix-02/prepared/component.rs)、[组件源映射](../tools/x230/20261105/reference-buffer/evidence/tooling-fix-02/prepared/source-map.json)、[原资格报告](../tools/x230/20261105/reference-buffer/reviews/r23-source-qualification-report.json)。

启动阶段只读取公开的 `/usr/bin/ssh`（846,888 B）、`/usr/bin/false`（26,936 B）及固定 shell 目标 `/usr/bin/dash`（129,784 B），共 1,003,608 B。两组均执行原 SHA pin load，定时循环执行完整 reference 比较；没有读取生产私有 profile、SSH config 或 known-hosts。每 arm/scenario 预热 8 次，四个场景各执行三块 ABBA，每 cell 256 次。这是预热后的公开文件组件筛选，不是冷盘读取测量。[冻结计划](../tools/x230/20261105/reference-buffer/evidence/plan.json)、[原始 setup 与全部样本](../tools/x230/20261105/reference-buffer/evidence/attempt-02/run.stdout)。

## 两次编译记录与唯一一次实际测量

**attempt01 保留为编译失败、零样本。** 编译器在输出元数据的 `serde_json::json!` 表达式 `[16384, 65536][index]` 处报告宏语法错误。原始 428 B stderr、失败 native 回执和二进制不存在读回全部保留；该失败没有被改写为成功，也没有性能样本可供筛选。[首次错误原件](../tools/x230/20261105/reference-buffer/evidence/attempt-01/compile.stderr)、[首次失败回执](../tools/x230/20261105/reference-buffer/evidence/attempt-01/native-compile-terminal-status.json)、[二进制不存在读回](../tools/x230/20261105/reference-buffer/evidence/attempt-01/binary-absent-readback.txt)。

随后单独授权的 **attempt02 是测试工具语法修正**：生成器与生成组件各只将该输出表达式括成 `([16384, 65536][index])`，测量代码、矩阵、门槛、依赖、编译参数与时限均不变。路径隔离到 `tooling-fix-02/` 与 `attempt-02/`；新 driver 固定原 plan/build-plan 的 SHA，只允许修正组件身份与这些路径变化。源码和生成器逐字差异、原 19 个冻结文件身份以及独立审查全部保留。这不是性能拒绝后的重新抽样。[精确修正 diff](../tools/x230/20261105/reference-buffer/evidence/tooling-fix-02/exact-correction.diff)、[工具独立审查](../tools/x230/20261105/reference-buffer/evidence/tooling-fix-02/independent-review.json)、[修正绑定](../tools/x230/20261105/reference-buffer/evidence/tooling-fix-02/build-plan.json)。

attempt02 的编译与唯一一次组件运行均实际成功，exit 0、无自动重试、无取消或超时，终态输出完整并 durable。编译使用 rustc **1.95.0** 与原资格构建留下的六个 opt-level=1 rlib；没有调用 Cargo、安装或重编依赖。组件编译参数保持 opt-level=1、LTO off、codegen-units=1、debug assertions/overflow checks 开启。实际编译回执被观察为终态后，到 run driver 启动间隔 **76.423430 秒**，满足冻结的至少 30 秒静置。实际安装的 6,319 B build-plan 已完整读回，与修正准备稿逐字一致；真实 driver 的 argv、环境和六个依赖身份也匹配。[安装计划原件](../tools/x230/20261105/reference-buffer/evidence/attempt-02/build-plan.json)、[读取回执](../tools/x230/20261105/reference-buffer/evidence/attempt-02/build-plan-transfer.json)、[编译版本](../tools/x230/20261105/reference-buffer/evidence/attempt-02/rustc-vV.stdout)、[编译回执](../tools/x230/20261105/reference-buffer/evidence/attempt-02/compile-receipt.json)、[运行回执](../tools/x230/20261105/reference-buffer/evidence/attempt-02/run-receipt.json)、[独立回执与算术审查](../tools/x230/20261105/reference-buffer/reviews/arithmetic-receipts-01.json)。

| 实际阶段 | Native job | 结果 |
| --- | --- | --- |
| 修正后编译 | `1a1aa4fccd6-fc05-40c5` | succeeded / exit 0 |
| 组件运行 | `1a1aa51d972-fc05-40ef` | succeeded / exit 0；唯一一次测量 |
| 既有结果收口 | `1a1aa532be9-fc05-4109` | succeeded / exit 0；未执行新负载 |

组件二进制为 21,080,224 B，SHA256 `6e0aca6c461018a1bd4b7f746174a5747d3ec9b28d494f5012a24fedb5c85d63`。compile receipt、run driver/receipt 和实际 file-info 一致；postflight 对记录的源码、依赖和二进制重哈希一致。二进制实体及 rlib 实体不入本取证目录，保留其身份和原构建绑定；本地独立审查比较实际记录，没有声称重新下载并散列远端 ELF/rlib。[二进制身份](../tools/x230/20261105/reference-buffer/evidence/attempt-02/component-file-info.json)、[收口报告](../tools/x230/20261105/reference-buffer/evidence/attempt-02/postflight.json)。

`machine-before.json` 是从实际 `run-driver.json.machine_before` 抽取的同一份快照，时间为 06:07:38.594836 UTC；对象和规范 JSON 字节均核对一致。它不是事后补采的运行前数据。`machine-after.json` 是收口时另取的观察，两者均只提供环境背景，不作 RSS 收益证据。[运行 driver](../tools/x230/20261105/reference-buffer/evidence/attempt-02/run-driver.json)、[运行前快照](../tools/x230/20261105/reference-buffer/evidence/attempt-02/machine-before.json)、[实际 finalizer 启动参数](../tools/x230/20261105/reference-buffer/evidence/attempt-02/native-finalizer-start.json)、[运行后快照](../tools/x230/20261105/reference-buffer/evidence/attempt-02/machine-after.json)。

`postflight.passed=true` 只表示实际回执、文件身份和样本收口成立；同一报告的 `mechanism_gate_passed=false` 与 `candidate_adopted=false` 明确表示性能候选未通过、未采用。原准备阶段的 README、notes、plan 和 manifest 保留原字节，其中“未运行”等字段描述准备时状态；当前最终决定以本文件和实际 attempt02 证据为准。[完整取证索引](../tools/x230/20261105/reference-buffer/README.md)。

## 安全、资源与结论范围

公开文件预检及结束复检通过：错误参考字节仍完成读取，最终内容错误仍会报出，取消/到期拒绝以及晚取消优先于内容不匹配均得到检查。但这不是全量 I/O 错误、owner 生命周期或运输故障资格。增大 buffer 后公开文件的内部 `check_current` 总次数从 **207 降到 69**；因此每字节取消检查更稀、竞态下错误的可观察先后可能改变，不能宣称取消时点不变或给出硬毫秒上限。每个活跃校验的栈数组还增加 **48 KiB**。[setup 预检原始记录](../tools/x230/20261105/reference-buffer/evidence/attempt-02/run.stdout)、[保留边界的冻结计划](../tools/x230/20261105/reference-buffer/evidence/plan.json)。

两个 arm 和参考字节同时驻留，组件编译优化环境也不同于 production release；这些线程 CPU 结果不能换算成 release RPC、六机作业启动或集群计算吞吐，也不能支持 RSS 降低。全局常量还影响私有 profile/config/known-hosts 的 SHA 路径及 SHA fallback，本次没有测试这些路径，不得推定整 profile 不回退。由于主门和小文件门已失败，本轮无需推进到生产改动或完整资格。[原始范围标记](../tools/x230/20261105/reference-buffer/evidence/attempt-02/summary.json)、[独立审查范围](../tools/x230/20261105/reference-buffer/reviews/arithmetic-receipts-01.json)。

因此本轮保留已通过完整六机验收并推送的 R24，不通过省略 fresh read、复用过期权威检查、放宽取消/deadline 或容量拒绝来换取吞吐。先前被拒绝方向的原证据继续保留；更大的并发、不同 worker 档或新的算法仍可能构成未来研究方向，但需要新的具体瓶颈证据和独立范围审查。当前失败结果足以关闭这一次 buffer 候选，不支持“再跑到通过”的扩展。[原始剩余边界 notes](../tools/x230/20261105/reference-buffer/evidence/frontier-notes.md)、[R24 已发布版本](https://github.com/TrillionniumFoundation/hepta-runtime/commit/baab4def80be7af015b2e7a594cb302f66c4130e)。
