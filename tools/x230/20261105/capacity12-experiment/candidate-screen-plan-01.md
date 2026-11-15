# Capacity12：预先选择的验收规则

**决策规则已预先记录；执行协议尚未冻结、候选未选择执行。** B 的真实 ELF、格式化后源码、资格/CI、完整 native recipe、磁盘和窗口均未绑定。本次只新增本说明与 [JSON 计划](candidate-screen-plan-01.json)，不改已有补丁、manifest、owner 文件或任何旧 gate。

## 基线、范围和资格

A 是 accepted R24，commit `baab4def80be7af015b2e7a594cb302f66c4130e`，实际 X230 ELF 为 `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13`（14,373,416 B）。B 仅为已绑定的 pooled global8→12、admitted固定16 两文件补丁；host2、master8、channel8、direct/cancel 均保持 R24。共享池的 opt-in file observation 也在范围内。Global budget 仍覆盖 authority、capture、返回检查和 caller retained output，不是 SSH 进程计数。

测量前，B 必须完成全量 X230 native 资格与原 Rust/Python CI。以 R24 实际 inventory 为基准：**1645 passed、0 failed、34 ignored、1679 selected、零重试**；须逐 target 比较完整 case 名与 ignored 状态，不能只比数量。原完整 audit 的远端身份已在 JSON 引用，但本次没有读取全部 case 名。50 个 pool isolated fixture kinds 保留；未来 formatter 产物仍须实际重算、核对 tested/release source map。B 的未知路径、SHA 和结果均为 null。

## 六机观察与新的容量采用条件

保留 ai395、mac、main、pocket4、rog、x230；workers2 / arena1；一次原固定 ABBA（四轮 A/B/B/A），客户端 C1/C8/C16。

| 必需条件 | 预先选择的边界 |
|---|---|
| C1、C8、C16 各档成功吞吐 | B/A ≥ 0.95 |
| 各档 RPC p95 | B/A ≤ 1.10 |
| 各档自身 CPU / 成功调用 | B/A ≤ 1.10 |
| Controller RSS | 同时 B ≤ A+512 KiB、B ≤ A×1.05 |
| 本候选额外采用条件：C16 成功吞吐 | **B/A ≥ 1.03** |
| 本候选额外采用条件：C16 自身 CPU / 成功调用 | **B/A ≤ 1.00** |

新 3% 主指标和 CPU 不增加条件是本容量假设的 **decision rule，不是观测结果**；不是将 compiler 的 C8 采用门挪给 C16。任一适用共同门失败即拒绝，即使 C16 达标。常量变为 12 本身不证明收益。

自身 CPU 只用同 PID/birth 的 utime+stime，不含 SSH、harness、waited-child 或远端 CPU；沿用原 aggregation 和完整零失败正确性校验。保留原 C32 capacity rejection、other-error=0、drain/recovery 验证（不把历史实际32/32结果改成固定计数门），以及六新作业/12 same-key/12 cancel 的完整 C6 canary 与独立审计。

## 正常 lifecycle 仍全部必需

另执行一次原 ABBA，保留 all_operations、launch、concurrent_cancel 三组各自吞吐 B/A≥0.95、p95≤1.10。CPU 原门为：B 组自身 CPU 总量 ≤ A 总量 + **每个选中 B phase/round 的一个实际 clock tick**；使用原 analyzer 的数值精度处理，不增加容忍量。RSS 仍同时满足 +512 KiB 与 ×1.05，取每臂两轮、每轮三代 controller 的最大实际采样值。原 policy/analyzer 的完整路径、大小与 SHA 在 JSON 中；其他阶段仍保留在 all_operations 与正确性证据内。

## Reserve saturation：明确不适用，绝不是通过

原 R25 scope 文档将该测试定为 **candidate-only direct cancellation-reserve** 新能力门，并说明旧 API 未承诺普通 direct 满载时的取消接纳。R25 增加 reserve；R26/R28 继承它。R24 的 same-key reconciliation 与 cancel 都进入同一 ordinary direct16/8/2，当前补丁没有新增 reserve 能力或承诺。

因此本次在任何 capacity12 测量前，明确固定 **applicability=false、result=null、is_a_pass=false**。原 gate 文件与要求完整保留：32 原 key 压力请求、16 pending/16拒绝、八个 held Child 身份不变、六 cancel 在 release 前确认、随后完整 drain/retire/restart/终态输出见证。它证明的是新增取消控制能力，不能平移为 R24 已有共同保证。若候选以后涉及 direct/cancel/reserve，必须重新判定范围并在测量前冻结新计划，不得沿用这个不适用结论。

R28 的“cache-only”不表示相对 R24 仅改 cache：其 actual qualified jobs/ssh/direct 源码仍保留并使用 reserve。它已因 C1 吞吐 -7.959385785% 失败，仍不采用、不原样再跑；本范围判断不改变 R26/R28 的原 gate 或结果。JSON 保留 R25 scope/manifest、R24 调用链、R28 实际 source-map/源码以及原 saturation verifier 的精确 SHA。

## 执行前仍阻塞

B 实际资格/ELF/CI、完整 case 名比较、native recipe 与输入/新输出目录、磁盘和执行窗口尚未闭合，当前不能启动。计划不生成执行器或请求、不共用 compiler/R28 运行目录。每项固定 ABBA 只做一次；失败不改阈值、不换 key 原样再跑、不挑选轮次，完整保留失败。未知 start 只用同一完整请求/同一 key 协调。无 training。若 accepted 不再是 R24，须重新绑定版本，不能给本计划改标签继续跑。
