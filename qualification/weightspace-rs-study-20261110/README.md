# HeptaRuntime Weight-Space 审计与窄范围 Rust 扩展

研究日期：2026-11-07。这个目录是独立、可编译的研究工件，不是正在运行的 HeptaRuntime 工作树，也没有注册 MCP 服务、激活模型或写入生产 checkpoint。

## 结论

**应复用已有 HeptaRuntime 权重 workbench、数学求解器、exact-edit 工件与恢复 owner。并非从零开发一个类似 REA 的新系统。** 本轮补充一个窄的 F32 稀疏列方向修改编译器，并实际重跑已有数学源文件的测试。它不推断电路，不搜索全局最优，不证明 Hepta Neuron 或 HeptaTrader 的端到端收益。

## 精确来源与现有实现

初始只读工作树是 `9f60a30530f47925f4f6ae495660a1d68bb6947d`。工作树采用稀疏布局；未出现在磁盘上的 `experiments/weight/mit_replay` 在该 commit 的 Git 树中真实存在，不能把稀疏缺席误当成“未实现”。

本目录 `upstream/manifest.json` 固定审计源为 [`bc38fb82244b946907886704b3c677bf00761cb9`](https://github.com/TrillionniumFoundation/hepta-runtime/tree/bc38fb82244b946907886704b3c677bf00761cb9)。15 个原始文件的 Git blob SHA-1 已逐个复核，另记录 SHA-256 与字节长度。原始 `.rs` 和测试未改写。审计时 [PR94](https://github.com/TrillionniumFoundation/hepta-runtime/pull/94) 为 open / draft / unmerged；不能把分支能力自动归到主干或 pocket4 的运行二进制。

| 已有层 | 已实现能力 | 数学和执行边界 |
|---|---|---|
| `weight_tensor` / `weight_artifact` | 完整源文件 SHA、精确 old/new 字节、F32/F16/BF16、独立候选、反向恢复工件 | 单张量、最多 1024 元素；无通用电路识别；不修改 live pointer |
| `weight_forward` | 有界 Rust F32 Linear forward | 不是完整 Transformer、CTMC 或 Hepta Neuron graph 执行器 |
| `weight_open/call/status/read/close` | 复用现有 durable process owner，inspect/probe/intervene/analyze/patch/seal/query | resident 数值 backend 仍可为受 pin 的 Python/PyTorch；“原生 transport”不等于“完整 Rust inference” |
| [PR91](https://github.com/TrillionniumFoundation/hepta-runtime/pull/91), `d85852b3c1708d9b2e8162badc07116999eff15e` | 固定特征 proximal weighted ridge、supplied-row 质量门、preservation/terminal/complement 约束 | 无梯度的监督凸拟合；不是无需标签，也不是 NDU 全局最优 |
| [PR92](https://github.com/TrillionniumFoundation/hepta-runtime/pull/92), `e7a2688acc5504412d45160a08d2bf864be6b650` | 多输出共用 L2 trust-region、F32 降低、576-bit 整数精确改变量预算 | 实数凸问题的 F64 残差是数值诊断；不证明离散 F32 参数最优 |
| [PR93](https://github.com/TrillionniumFoundation/hepta-runtime/pull/93), `990f85e46bedb8f49c0e6d0029ea6f9afbf6eac7` | 固定有限 DAG Bellman、持久 guarded 请求恢复 | 给定转移图的 DP；不认证真实环境定律；中断请求保守拒绝 |
| [PR94](https://github.com/TrillionniumFoundation/hepta-runtime/pull/94), `bc38fb8…` | 固定 85/48/4 checkpoint、147 continuation 参数的 exact binary64 不可行证书 | 只排除指定表示/半径下复制指定排序；不排除部分有用编辑，也不证明任何新表示都无效 |

PR94 的 PR 正文记录历史官方 CI：all-features 1816 passed / 41 skipped，no-default-features 1796 passed / 29 skipped，运行 `41966037157`。**这些是该 PR 的历史证据，本轮没有重新执行其完整 MCP/文件/进程/恢复测试。**

旧 checkout 的 `experiments/weight/mit_replay/RESULTS.md` 已记录 p50c 的 28 次实际 paired forwards，以及先前失败尝试的 4 次 forwards；公开选定上下文的机制重放不是 blind MATH/GSM8K benchmark。本轮主任务另有专门的 MIT replay 工作，本目录不重复计入其结果。

## 本轮新增的可执行小组件

`src/mcp/projection.rs` 将事先给定的单位方向 `u`、列集合 `J` 和剂量 `alpha` 编译为：

\[
W'_{:,J}=W_{:,J}-\alpha u(u^T W_{:,J}).
\]

每个投影从不可变基座计算，其他列保持逐 bit 相同；F64 计算后显式转换为 F32，并以实际存储差异生成已有 `ExactElementEdit` 的 `index/expected_hex/replacement_hex`。受限坐标编辑共用相同校验和预算路径。两者均无梯度步骤。

检查包括完整源文件身份承诺、张量数据 hash、name/shape/dtype schema hash、冻结 protocol hash、protected tensor 名称、有限值、尺寸、重复列/坐标、expected bits、F32 overflow、存储舍入 no-op、最多 1024 touched elements，以及每坐标和整体 L2 改变量。后两者直接调用**原始 `weight_norm.rs` 的 exact represented-number 校验**，没有以 epsilon 放松边界。

本规划器接收已验证 tensor snapshot；此处 SHA 只绑定调用方提供的 source identity，**不会自己认证 safetensors 文件内容或调用者身份**。接入时仍必须让 `weight_artifact` 通过 confined descriptor 重新认证完整文件及 expected bytes。计划不是执行权限，也不是生产资格。

`alpha=1` 沿 `u` 去除选中列分量；`alpha=6` 则把该分量变成原来的 `-5` 倍。它不能被描述为纯正交投影。测试特意验证这一点。

**真实 MIT Qwen p50c 修改不适合直接塞进这个窄接口**：每张量 `1024×3584`、64 列，选中 65,536 元素；两张量 131,072 元素。当前 native exact-edit 单次 cap 是 1024。规划器对超额请求拒绝，绝不悄悄拆成多个非原子修改。若要扩大，需要已有 owner 下的多张量 cohort manifest、整体基座/预算、成组发布与反向恢复语义；已有 Python worker 的 typed writer projection 是另一条现成研究路径。

## 确认集与回滚演示的明确范围

`src/mcp/confirmation.rs` 是小型**内存中研究合约演示**，用于指出 native supplied-row guard 的实验治理接口应如何接合，并不替代 `weight_guard_journal`。

- 校准与确认分区、基座、阈值在 candidate 之前冻结到 protocol hash。
- 精确 input-content hash 与 row ID 检查交叉重叠；确认行在计算前被消耗，失败也不归还。改标签、改 row alias 不能绕开 exact input 复用检查。
- 所有 primary rows 必须严格越过预定增益，独立 regression rows 的逐输出变化必须在界内；一个平均数不能掩盖保留能力退化。
- 候选仅暂时进入研究 preview pointer；拒绝或有限行前向错误把 pointer 恢复到原值；原始张量没有被写过。
- base/patch/eval 记录只通过只读 API 暴露，事件链有内容 hash；CLI 以 `create_new` 写证据并 fsync。

这些约束不证明统计独立、从未见过数据、数据来源真实、或者跨进程/重启不可复用。日志没有签名，不是 WORM 存储。此 demo 的 ledger 不持久承载授权，进程退出就失去防复用状态；代码和收据均输出 `independent_holdout_verified=false`、`durable_ledger=false`、`production_eligible=false`。生产接入应该把 split consumption 与原有 durable owner 的请求日志和外部 evaluator authority 绑定，而非增加另一个 executor 或“靠 hash 宣称独立”。

## 实际新执行结果

见 `evidence/final-tests.log`、`evidence/demo-final/report.json` 和 `evidence/summary.json`。

本轮使用原始上游数值源和原始测试，先完成 **45 passed / 0 failed / 1 ignored**。增加投影和确认合约风险测试后，最终为 **62 passed / 0 failed / 1 ignored**。ignored 项要求另行授权的真实线性头 NumPy fixture，本轮未把 synthetic fixture 冒充真实 checkpoint。

必须保留的测试环境差异：

- 编译器为 Rust 1.99.1；上游声明最低 Rust 1.95。
- `rmcp` 仅以 `schemars` re-export 做类型/schema 测试壳；未启动或测试 rmcp transport。
- 离线环境缺少 `serial_test`，采用明确的测试宏 shim，并强制执行 `--test-threads=1`；不声称原始 serial_test 机制已合格。
- 本地 cached `num-bigint=0.4.8` 替代上游锁定 `0.5.1`，因此 exact-certificate 源代码测试通过**不是原始依赖闭包的软件资格**。
- tokio 1.53.3、serde_json 1.0.154、sha2 0.11.1 等实际版本以 `Cargo.lock` 为准。

三个 CLI 案例均为人工植入缺陷的 synthetic 1×2 线性头：

| 案例 | 已观察的 preview 结果 | 意义 |
|---|---|---|
| `known_repair` | 校准/确认 primary 提升且 regression 保持，接受研究 preview | 编译和门控通路可运行；不是未知缺陷定位能力 |
| `quality_rejection` | 确认集劣化，拒绝并恢复原 preview hash；复用被拒绝 | 拒绝/恢复合约可运行 |
| `regression_rejection` | primary 提升，但 regression 变化，拒绝并恢复 | 防止仅看主指标的错误接受 |

曾发生两个 harness 构建失败：首次缺 `serial_test`；第二次离线 cache 无该 crate。失败日志保留，随后只修复测试壳；未改写上游原始代码去让测试通过。

## 复跑命令

在本环境，缓存与工具链位于其它只读项目的预装目录。本工程只写自己的 `target/` 和新输出目录：

```bash
export CARGO_HOME=/workspace/scratch/62902f6722b7/cargo-next
export RUSTUP_HOME=/workspace/scratch/9fda32f7f9ab/ndu-native-setup/rustup
export PATH=/workspace/scratch/9fda32f7f9ab/ndu-native-setup/rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH
cargo test --offline --locked -- --test-threads=1
cargo run --offline --locked --bin projection-demo -- /absolute/new/output-directory
python3 verify_evidence.py
```

输出目录必须不存在；已完成证据不会被 demo 覆盖。运行命令不会使用 GPU，不下载依赖，不训练网络，不启动交易服务。

## MCP 整合与仍未验证的范围

建议新增的只是一个纯规划入口，将已验证 tensor snapshot 与有限 `ProjectionSpec` 编译成 `ExactElementEdit`；source authentication、candidate publication、guarded forward、restore、request reconciliation 继续由现有 owner 完成。Agent 规划/数值分析与执行授权应保持分离：`execution_shadow_admit` 的 `shadow_only` 和 `final_use:not_granted` 不能当作可执行许可。

现有 `weight_guarded_linear_patch` 的标签和 inputs 同时来自调用方，源码明确不认证 independent holdout。完整科研系统需要外部 evaluator 管理未来分区、adaptive query 预算和完整分母，再将其回执接回现有 journal。原有 Python experiment/evaluation 协议可复用；“native guard 没有此能力”不代表整个研究仓库没有相关验证程序。

仍未实现或本轮未验证：全网模型图和因果机制的自动定位；First-Passage/Reset 的统一 generator/value/reset 编译；Call/Put 的正确 survival mass/货币单位；Belief 的真实校准；不同表示间等价性；closed-loop NDU 或前瞻交易净收益；跨重启 split 防复用；多张量原子提交；完整 runtime transport、文件权限、journal crash recovery 和运行 binary currentness。本目录不能将这些缺口包装成已完成。

## 发现的文档漂移

同一 `bc38fb8…` 的 `docs/native-weight-guard.md` 仍称“guard 不支持 parameter norm / trust region”和“没有 durable evaluation journal”。实际 `weight_guard.rs` 已校验 `max_update_l2_norm`，且 public `evaluate` 委派给 `weight_guard_journal::evaluate_with_roots`。日志层还会覆盖底层 helper 的 `durable_evaluation_receipt` 等字段。应修订旧文档，不能根据过时文字再实现一个重复框架，也不能因为 helper 的局部 false 字段而误报外层无日志。

此处只报告问题，没有修改现有 repository 或 PR。
