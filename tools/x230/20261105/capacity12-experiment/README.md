# Pooled observation global 12：未选择执行的源码候选

**prepared / unselected / uncompiled。** 本目录只保存两个修改后的 Rust 文件、相对 R24 的 [补丁](capacity12.patch) 和 [身份清单](manifest.json)。没有 native 调用、Cargo/rustc/rustfmt/clippy/test、基准、GitHub 写入或采用结果；原生执行窗口仍属于 owner 的 reservation26。

## 来源与改动

基于当前已接受的 R24：commit `baab4def80be7af015b2e7a594cb302f66c4130e`，src tree `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`。实际输入来自 `r24-tested-source`，两个文件的 SHA256 均与原 qualified source map `c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd` 匹配。

最初指定的 `r24-candidate/source` 可用来读 AGENTS 和同字节 pool，但其中测试文件是 fmt 前版本。本包使用 qualification map 绑定的 fmt 后测试文件，没有把未绑定副本作为补丁基线。完整路径、字节数、原件与候选 SHA 在 manifest 中。

| 项目 | R24 | 候选 |
|---|---:|---:|
| Pooled observation global budget | 8 | 12 |
| 全生命周期 admitted identities | 16 | 16，改为独立常量 |
| 每 host budget | 2 | 2 |
| master entries | 8 | 8 |
| channel slots | 8 | 8 |

生产代码只修改 `MAX_SESSIONS` 和 `MAX_ADMITTED` 的取值/表达式，另更新模块中文说明及过时的 global8 注释。没有改 permit 获取顺序、失败冻结、取消、子进程 custody、返回检查或 drop 路径；direct SSH/cancel、profile/CLI、validation workers、allocator 和 runtime workers 文件均不在补丁内。

这里的 global budget 同时约束 initial authority check、capture、返回 authority check 和 caller 持有的 `Captured` 输出，**不等于实时 SSH 进程数**。共享同一池的 opt-in file observation 也使用 global12；本包不增加 status/read 专用选择逻辑。

## 既有测试的必要适配

没有新增测试函数或删除原 isolated fixture 分支。只调整容量解耦后不再成立的 fixture 假设，并加强既有固定 16 接纳边界：

1. `queued_proxy_waiters_keep_sixteen_identities_and_send_each_request_once` 实际只提交 16 个身份，再验证第 17 个在首次 poll 拒绝；循环/最终数量不再跟随可能误扩大的 `MAX_ADMITTED`。
2. `fair-retained` 和 `phased_preflight_fixture` 在仍为 8 的 channel 满时等待原 actor 排空，再投递其余请求。没有扩大测试 channel，也没有把预算缩回 8。
3. `queued_admission_fixture` 使用 `admitted - global` 的剩余身份数；`fair-retained` 验证 12 个实际返回并仍被 caller 保留的输出，仅余 4 个逻辑身份。停止、关闭、拒绝、释放一个预算只放行原待处理请求的覆盖均保留。
4. `fair-cancel-deadline` 在全部 12 个输出预算仍被持有时，分阶段容纳取消、已过期、caller 关闭、未知 host、将来到期以及仍等待的请求。每个原错误断言都保留；全局预算在这些拒绝期间始终不释放。`output-10`/`output-11` 出现后，对两侧预期/实际 command 都按字符串顺序比较，消除原 0–7 隐含排序假设。

这些是源码静态核对结果，**不是测试通过声明**。完整 native format、clippy、资格测试、实际 CI 和资源/正确性压力验收都还未执行。

## 资源与后续选择边界

现有每条 stdout/stderr 捕获 payload 各最多 8 MiB。仅按同时被 global budget 持有的请求输出算术，8 × 16 MiB = 128 MiB，12 × 16 MiB = 192 MiB，上界增加 64 MiB。该值不包含其他分配和 SSH 进程，不是实际 RSS、峰值或吞吐预测。

尚无证据证明 global8 是现有瓶颈，也没有实际 global12 结果。本包没有创建或修改性能计划和门槛。若后续选择这个容量假设，应在运行前另行冻结它的六机比较目标、容量证据及性能/资源门槛，并保留现有正确性与非回归要求；不能把编译器候选的 C8 增益门槛挪作 C16 容量提升的证明。届时如 accepted 已变为 R28 或后续版本，必须重新核对实际源文件与版本绑定；不能把本包的 R24 身份改写为新版本。
