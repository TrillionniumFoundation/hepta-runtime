# X230 capacity12：未执行的观察池容量候选

**prepared / unselected / uncompiled。** 本检查点保存源码候选与预先选择的决策规则。候选没有执行格式化、编译、测试、CI 或性能验收，也没有被采用；没有实际 B ELF 或吞吐、CPU、RSS 结果。当前已采用基线仍为 R24。容量是否是瓶颈、这个候选能否改善性能、是否已达到全局最优，都尚未证明。

计划以 commit `1c23ba9ad4e7c9436eb76d1508f6f0bd8ee7ce64`、tree `91ef72ae803bede6a2b2d8e8eb8f25da95ad170b` 为固定父版本，保存到独立实验分支 `experiment/x230-capacity12-20261105`。本检查点包含两个实际 `src` 变更；shared/default 分支不在更新范围。

## 导航与原始记录

| 内容 | 文件 |
|---|---|
| 两个实际修改的 Rust 文件 | [ssh_observation_pool.rs](../src/mcp/runtime/ssh_observation_pool.rs)、[ssh_observation_pool_tests.rs](../src/mcp/runtime/ssh_observation_pool_tests.rs) |
| 相对已资格验证 R24 源码的完整补丁 | [capacity12.patch](../tools/x230/20261105/capacity12-experiment/capacity12.patch) |
| 准备时的源码身份、边界与静态核对 | [manifest.json](../tools/x230/20261105/capacity12-experiment/manifest.json)、[README.md](../tools/x230/20261105/capacity12-experiment/README.md) |
| 预先选择的采用规则及执行阻塞 | [计划说明](../tools/x230/20261105/capacity12-experiment/candidate-screen-plan-01.md)、[结构化计划](../tools/x230/20261105/capacity12-experiment/candidate-screen-plan-01.json) |

`tools` 中五份记录按准备时原字节保存。其中绝对路径和未执行、未发布字段描述当时的本地准备状态，没有为本检查点改写历史。两个修改后的源码文件只放在仓库的 `src` 路径，不在 `tools` 重复复制；文档与计划不能替代未来的实际资格和测量证据。

## 最小生产变更与资源范围

基线为 accepted R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`，src tree `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`。生产运行代码仅两个常量变化：将 pooled observation 的 `MAX_SESSIONS` 从 8 改为 12，将 `MAX_ADMITTED` 从原来的 `MAX_SESSIONS + QUEUE` 解耦并固定为 16。另更新了模块中文说明和过时注释。

| 资源域 | R24 | 候选 |
|---|---:|---:|
| Pooled observation global budget | 8 | 12 |
| 全生命周期 admitted identities | 16 | 16 |
| 每 host budget | 2 | 2 |
| Master entries | 8 | 8 |
| Channel slots | 8 | 8 |

Global permit 仍覆盖 initial authority、capture、返回 authority 和 caller retained `Captured` 输出，不能解释为同时存在的 SSH 子进程数。共享同一池的 opt-in file observation 也受 global12 影响；本候选没有增加 status/read 专用选择逻辑。Direct SSH/cancel、验证 worker、runtime worker、allocator，以及 permit/custody/drop/abort 实现均未改。

现有每请求 stdout/stderr payload 各最多 8 MiB；仅按 global budget 的输出 payload 算术，上界由 8×16 MiB=128 MiB 变为 12×16 MiB=192 MiB，增加 64 MiB。这不是实际 RSS、全部进程内存上界或性能预测。

## 源码来源与测试状态

补丁基于 R24 实际资格 source map 绑定的 `r24-tested-source`。最初的 `r24-candidate/source` 测试文件为 fmt 前 91,734 B，SHA `5e12d5fa158c8a2c5ec6abc433245398ac9276fa2e21256d10ef7262c92f8c2e`；实际采用的基线测试文件为 fmt 后 91,747 B，SHA `c41347b04e3697503dd0f75237b66c7bb24c512b5bc9362cf7d9a5525e843a7c`。两者差别是一个原 assert 的格式。本候选从后者修改，**不表示当前候选本身已经格式化或验证**。

静态对比保留原 50 个 pool isolated fixture kinds 和函数名，没有新增测试函数。必要适配包括 channel8 满时分批投递、12 retained output 后只余四个身份、取消/过期/关闭/未知 host 等错误案例分阶段容纳，以及 `output-10`/`output-11` 的字符串排序；原第 17 个身份首次 poll 拒绝被固定为真实的 16 个请求。静态 peer 未发现阻断项，但没有运行这些测试。

计划中的 **1645 passed、0 failed、34 ignored、1679 selected、0 retry** 是 R24 基线的实际 inventory，也是未来候选必须完整保持的预期，绝不是本候选结果。B 还须逐 target 比较完整 case 名与 ignored 状态，核对实际 formatter、tested source map 和 release 输入；实际 B ELF、资格与 CI 记录目前均为 null。

## 本候选预先选择的决策规则

六机沿用 ai395、mac、main、pocket4、rog、x230，workers2/arena1，一次原固定 ABBA（A/B/B/A）。完整 workload、输入、采样和新运行目录仍须在执行前绑定。

| 必需条件 | 规则 |
|---|---|
| C1/C8/C16 各档成功吞吐 | B/A ≥ 0.95 |
| 各档 RPC p95 | B/A ≤ 1.10 |
| 各档控制器自身 CPU / 成功调用 | B/A ≤ 1.10 |
| Controller RSS | 同时 B ≤ A+512 KiB、B ≤ A×1.05 |
| 本容量假设额外要求：C16 成功吞吐 | **B/A ≥ 1.03** |
| 本容量假设额外要求：C16 自身 CPU / 成功调用 | **B/A ≤ 1.00** |

3% 和 CPU 不增加条件在本候选测量前选择，尚无结果；没有套用 compiler 候选的 C8 采用门。任一适用共同门失败即拒绝，即使 C16 达标；将预算改成 12 本身不算收益。自身 CPU 使用同 PID/birth 的 utime+stime，不把 waited-child、SSH、harness 或远端 CPU 混入。

原 C32 边界、容量拒绝、other-error=0、drain/recovery 与完整 C6 canary 继续必需。正常 lifecycle 另做一次原 ABBA：all_operations、launch、concurrent_cancel 各组吞吐 B/A≥0.95、p95≤1.10；自身 CPU 保留每个选中 B phase/round 一个实际 clock tick 的原容忍；RSS 同时满足 +512 KiB 与 ×1.05。完整规则、聚合方法和原 policy/analyzer 身份见计划。

## 原 reserve saturation 门的适用范围

原 R25 scope 文档将该门归于新增 direct cancellation reserve，并明确此前 API 未承诺普通 direct 满载后的取消接纳。该文档 SHA 为 `344148096d20937e62772e2b4592ca5a2f0d6ba333239f522a6848752d2337d9`；原 reserve candidate manifest SHA 为 `b02c9c8e8b2fb474a40b5a4783c1697e9397ac5a6efbca727bd4dfbdaca43835`。精确路径与后续 verifier 身份均保留在结构化计划的 evidence 中。

R24 的 [jobs.rs](../src/mcp/runtime/jobs.rs) 中 start/reuse 继续调用 `status_record`，`cancel_job` 调用普通 Python/jobctl 路径；[ssh.rs](../src/mcp/runtime/ssh.rs) 最终进入 [ssh_direct.rs](../src/mcp/runtime/ssh_direct.rs) 的同一 ordinary admission16/global8/host2。当前补丁不改变这些文件，没有新增 reserve 能力或承诺。

因此，在任何 capacity12 测量前明确记录 **applicability=false、result=null、is_a_pass=false**。原 gate 及其 32 原 key 压力调用、16 pending/16拒绝、八个 held Child 身份不变、六 cancel 在 release 前确认、完整 drain/retire/restart/终态输出见证等要求都保留，没有改写成通过。若未来触及 direct/cancel/reserve，必须重新冻结范围，不能沿用本次不适用结论。

R28 的“cache-only”不表示相对 R24 仅改 cache：其实际 qualified jobs/ssh/direct 仍继承并使用 reserve。R28 已因 C1 成功吞吐 −7.959385785% 被拒绝，本检查点没有修改或重跑其失败结果。这里是新候选的事前范围判断，不是为已有失败放宽门槛。

## 当前阻塞与采用边界

执行仍需真实 B ELF、全量 X230 native 资格、原 Rust/Python CI、完整 case 名对照、精确 native recipe/输入/输出绑定、可用磁盘与独占执行窗口。计划没有生成执行器或测量请求，不共用 compiler/R28 运行目录。失败不改阈值、不换 key 原样再跑、不挑选轮次；未知 start 仅按同一完整请求和同一 key 协调。无 training，未证明全局最优。若 accepted 版本改变，先重新绑定实际版本与源码，不能给本检查点换标签继续使用。
