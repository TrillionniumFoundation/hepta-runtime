# X230 reference-buffer 最终取证

**最终决定：64 KiB 未通过冻结组件门，未采用；生产 R24 保持 16 KiB。** 完整公共三文件 thread CPU 从 328.638698 µs 降至 309.998305 µs（−5.672%，要求至少 −20%）；false 从 36.747514 µs 增至 37.754157 µs（+2.739%，上限 +2%）。这是一次完整、有效但性能门失败的组件测量。[最终说明](../../../../docs/X230_OPTIMIZATION_20261105_REFERENCE_BUFFER.md)、[实际摘要](evidence/attempt-02/summary.json)、[独立重算](reviews/arithmetic-receipts-01.json)。

## 状态与两次尝试

| 项目 | 事实与取证 |
| --- | --- |
| 生产版本 | R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`，16 KiB；[实际发布读回](reviews/r24-accepted-publication-readback.json) |
| attempt01 | 输出元数据的 JSON 宏语法错误，编译 exit 1，零样本；[stderr](evidence/attempt-01/compile.stderr)、[native 终态](evidence/attempt-01/native-compile-terminal-status.json)、[二进制不存在读回](evidence/attempt-01/binary-absent-readback.txt) |
| attempt02 修正 | 只给输出索引表达式加括号，以及隔离路径/hash pins；[精确 diff](evidence/tooling-fix-02/exact-correction.diff)、[静态独立审查](evidence/tooling-fix-02/independent-review.json) |
| attempt02 编译/运行 | 原有 native supervisor，两阶段 exit 0、无重试/超时/取消；[编译回执](evidence/attempt-02/compile-receipt.json)、[运行回执](evidence/attempt-02/run-receipt.json) |
| 唯一一次测量 | setup + 48 samples + complete，50 条；[完整 JSONL](evidence/attempt-02/run.stdout)、[stderr](evidence/attempt-02/run.stderr) |
| 实际门 | triplet ≤0.80 失败，false ≤1.02 失败，shell ≤1.02 通过；所有样本纳入，[逐 cell/块/汇总重算](reviews/arithmetic-receipts-01.json) |
| 收口 | `postflight.passed=true` 是取证收口；性能门和采用标志均 false，[原件](evidence/attempt-02/postflight.json) |

attempt01 的失败未改写；attempt02 是发生在任何性能样本之前、单独授权的工具语法修正，不是性能失败后的抽样重试。源码参数、3 块 ABBA、每 cell 256 次、每 arm/scenario 8 次预热、全部门槛与依赖都保留。该目录中的原准备文件保留原字节，历史 `prepared/not run` 状态不代表最终状态；最终结果以本 README、实际回执和样本为准。

## 证据布局

| 路径 | 内容 |
| --- | --- |
| [evidence/plan.json](evidence/plan.json) | 原冻结参数、范围、门槛与停止条件 |
| [evidence/README.md](evidence/README.md)、[frontier-notes.md](evidence/frontier-notes.md) | 原始准备说明/剩余空间边界，未改写历史状态 |
| [evidence/execution-binding-note.json](evidence/execution-binding-note.json) | R23 资格源与 R24 已完成采纳之间的额外执行前提 |
| [evidence/prepared/component.rs](evidence/prepared/component.rs)、[arm-diff.txt](evidence/prepared/arm-diff.txt) | 原组件及 16/64 KiB arm 差异 |
| [evidence/buffer_screen.py](evidence/buffer_screen.py) | 原生成器、绑定器和原 summarizer |
| [evidence/tooling-fix-02/manifest.json](evidence/tooling-fix-02/manifest.json) | 修正版 helper/component 的完整身份与安装映射 |
| [evidence/tooling-fix-02/prepared/component.rs](evidence/tooling-fix-02/prepared/component.rs) | 实际编译的修正组件 |
| [evidence/tooling-fix-02/build-plan.json](evidence/tooling-fix-02/build-plan.json) | 从实际 attempt01 binding 派生的修正计划；编译 flags、原六个 rlib 身份、环境及限额 |
| [evidence/attempt-01/build-plan.json](evidence/attempt-01/build-plan.json) | 首次真实绑定原件，后续修正 driver 固定其 SHA |
| [evidence/attempt-02/build-plan.json](evidence/attempt-02/build-plan.json)、[读取回执](evidence/attempt-02/build-plan-transfer.json) | 实际安装计划的完整读回，与准备稿的 6,319 B 逐字一致；真实 driver argv/env/六依赖也一致 |
| [evidence/attempt-02/compile-driver.json](evidence/attempt-02/compile-driver.json)、[run-driver.json](evidence/attempt-02/run-driver.json) | 实际 argv、输入身份、环境及运行前观察 |
| [evidence/attempt-02/rustc-vV.stdout](evidence/attempt-02/rustc-vV.stdout) | 实际 rustc 1.95.0 完整版本输出 |
| [evidence/attempt-02/component-file-info.json](evidence/attempt-02/component-file-info.json) | 21,080,224 B 组件 ELF 的身份；实体不打包 |
| [evidence/attempt-02/machine-before.json](evidence/attempt-02/machine-before.json)、[machine-after.json](evidence/attempt-02/machine-after.json) | 前者逐字提取实际 run-driver 快照，后者为收口时观察 |
| [evidence/attempt-02/native-finalizer-start.json](evidence/attempt-02/native-finalizer-start.json) | 证明前快照抽取来源的真实执行参数 |
| [reviews/r23-source-qualification-report.json](reviews/r23-source-qualification-report.json) | 组件来源完整资格报告及 220 项 source_tested/source_after |
| [evidence/tooling-fix-02/prepared/source-map.json](evidence/tooling-fix-02/prepared/source-map.json) | 完整 220 项源输入映射 |
| [evidence/qualified-source/src/mcp/runtime/ssh_observation_profile.rs](evidence/qualified-source/src/mcp/runtime/ssh_observation_profile.rs)、[validation](evidence/qualified-source/src/mcp/runtime/ssh_observation_validation.rs)、[reference tests](evidence/qualified-source/src/mcp/runtime/ssh_observation_reference_tests.rs) | 供组件提取的三个完整已资格源文件，与已采用 R24 中相应文件字节一致 |
| [reviews/arithmetic-receipts-01.json](reviews/arithmetic-receipts-01.json) | 独立整数/Fraction 算术、source-glue、回执、依赖/二进制身份、76.423430 秒静置核对 |
| [reviews/receipt-independent-01.json](reviews/receipt-independent-01.json) | 另一独立审查者只读核对实际 native 回执、源码/二进制绑定、postflight 和快照来源 |
| [evidence-identities.json](evidence-identities.json) | 本目录证据文件完整大小、SHA256 与来源索引 |

所有原件按完整字节复制；ELF/rlib 实体、私有配置与密钥不进入本目录。完整 profile 源码是仓库 Rust 代码，不是用户 profile 配置正文。远端二进制和依赖的身份由实际 driver、receipt、file-info 与 postflight 相互约束；本地复核未重新读取其实体。

## 使用范围与停止依据

本次是使用现有 opt-level=1 依赖、单次独立 rustc 的公开文件组件筛选，没有 Cargo/dependency 重建。它保留完整 fresh reads、文件戳和真实取消/到期检查，但不包含完整 owner/worker 生命周期、SSH 运输或 RPC。全局 buffer 常量还影响私有 SHA 输入与 SHA fallback，这些未覆盖。两个 arm 同时驻留，不能比较 RSS；64 KiB 每个活跃校验增加 48 KiB 栈数组，并降低每字节检查频率。

全部 48 cell 已收口且主门/小文件门失败，故停止这个候选，R24 源码和容量/取消契约不变。组件 CPU 改善不能直接解释为集群或作业启动吞吐，更不能视为全局最优证明。任何未来方向需要新的具体瓶颈证据；本目录没有自动重跑或参数搜索结果。
