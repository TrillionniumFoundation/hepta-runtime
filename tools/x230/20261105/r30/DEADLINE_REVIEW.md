# R30 observation deadline：只读代码复核

## 结论与证据边界

本报告分析父任务提供的原始事实：R30 的第二个 B 轮 C1，ROG `process_status`，wire request_id 72，耗时 10,010.97226 ms，错误为 `observation transport deadline; no automatic retry`；4 轮共 2304 次请求仅此一条失败，前后同 host 请求恢复，所有原 controller 的 shutdown/restart 检查通过。没有重跑、远程调用或源码修改，也不把此次失败归因于 router、网络、SSH agent 或机器环境。

该精确错误文本只在 `ssh_observation_pool.rs::capture` 的 `timeout_at(deadline, receive)` 产生：外层等待 owner actor 的 oneshot 结果时触发了计时器。它说明 enqueue 已返回成功，不能证明 SSH 子进程已启动，也不能证明远端 helper 尚未完成。`enqueue` 自身的 reserve 超时另有 `observation queue admission deadline` 文本，16 个 admission 身份耗尽也有独立的 capacity 错误。

本地所读 pool 文件 SHA256 为 `92592431b6f4f0d3561c039ed86d9129f3942fb677ba9a336f639003b16b71d9`。该文件以及 `ssh.rs`、`ssh_observation_profile.rs`、`ssh_observation_validation.rs`、`ssh_observation_postspawn.rs` 均与冻结 R24 baseline_compile_inputs 完全一致。

## 同一个 deadline 覆盖哪些阶段

`capture` 在 enqueue 前建立绝对 deadline；成功提交后的 reply 等待继续使用这个 deadline，不重新计时。

| 阶段 | 同一请求预算中的等待或工作 |
|---|---|
| 入队与分派 | reserve 已消耗的时间、actor pending、初次 global admission；总身份 16、channel 8、global 8 |
| 第一次权限核验 | validation 两个 worker 的排队和完整文件读、owner 线程再次完整读、SSH agent 身份帧、第二次文件核验 |
| host / master / lease | host 两个 permit、master generation ready 或 renewal、global permit 再取得、第二次完整权限核验、original Child 存活检查、控制 socket / peer 核验 |
| slave | 原 Child 创建和 post-exec 证明、stdin 全写并关闭、stdout/stderr EOF、original Child wait、错误后的停止和回收 |
| response | 第三次完整权限核验、socket stamp 复核、结果通过 oneshot 交回 |

外部 router lookup、owner / request audit begin、job reference 检查，以及 capture 成功后的 JSON 解析 / completion audit，不属于这个 pool deadline 的起止区间。`process_status` 调用 `status_observation(record, 0)`；PythonStatus 的预算为 `min(wait_seconds,30)+10` 秒，与本次约 10 秒一致。SystemStatus 预算是 20 秒，最终可用原冻结 job 的 `system_jobctl` 字段确认所走分支。观测总耗时还含池外开销，不能把额外约 11 ms 直接解释为某个阶段耗时。

## 可以确定的竞争：细分错误会被外层 deadline 遮住

`captured` 的内部 SSH I/O 计时器也使用同一个 deadline。内部超时后会先 `stop_child(..., ZERO)`，再证明回收并 `release`，随后 `execute` 才发送结果。外层 `capture` 可以在这些清理完成前先到期；其 CancelOnDrop 会取消请求，oneshot 接收端随返回被释放。此后 `let _ = request.reply.send(result)` 会丢弃迟到结果，生产代码没有记录它的阶段或错误链。

这是明确的结果交付 / 超时竞争与诊断信息缺口，不能据此断言它就是本次 10 秒耗尽的起因。当前源码不保证通用 transport deadline 带有内部 SSH、host/global queue、authority 或回收阶段。远端已有输出、甚至 slave 已回收而 response authority 尚未完成，也可能得到该通用错误。

未发现足以认定本次事件由清理死锁或错误释放容量造成的代码证据。原 Child / pidfd 与 permit 保留到可证明回收；失败会停止 pool 并保留未解决的 custody。actor 停机等待原任务和 validation drain。已有测试覆盖 caller drop、晚到 worker、post-exec deadline、原 Child 回收及慢 host retirement。最终 shutdown 成功证明最终收束，不能证明该请求在 deadline 前处于哪个阶段。

## 当前能用与不能补出的证据

- 原 benchmark / wire capture 可绑定 host、tool、job、wire id、开始时间、耗时、响应 / 错误和前后请求。C1 只限制 benchmark 自身同时一个调用，不能直接推出所有 pool、master lifecycle 或遗留清理任务为空。
- 原 controller stderr、request audit 和资源监测可以核实响应来源、外围审核时间和最终退出。durable request audit id 是另一套身份，不能把 wire 数字 72 当作它；现有 audit 也没有 pool 的 queue / host / phase 时间线。
- `process_status` 的 job completion audit 只在 observation 成功后执行，失败没有该成功条目不代表 helper 没执行。
- 当前生产 `ssh_observation*` 路径没有阶段 tracing；master stderr 被有界读取并丢弃。测试的 phase_notice 不是生产 telemetry。旧 `HEPTA_OBSERVATION_TRACE` 在当前 pool 源码没有 consumer，不能靠启用旧变量补出阶段证据。
- request-scope 的 typed AgentLookupDeadline 可使单请求失败而后续请求恢复；其它正常请求也可在某一请求 deadline 后继续。仅凭恢复现象无法选择其中一种解释。

## 最小下一步诊断需求

先保留该原始失败，不覆盖或过滤：读取 row 72 的完整 wire 请求 / 响应及时间绑定、原 job 的 system_jobctl、同 controller 的相邻请求与 stderr、原 shutdown 和采样回执。这些数据能收窄预算分支与关联，不能重建从未记录的阶段。

若以后安排独立诊断版本，最少新增一个与 wire 调用关联的本地 request 序号、host alias、原 deadline，以及有界阶段时间线：enqueue、actor dispatch、authority 子阶段、host/master/global 就绪、spawn/post-exec、stdin 关闭、stdout/stderr EOF、child wait/release、postresponse verify、reply send 成功与否、cleanup 完成。仅在 enqueue / deadline 取 pending 数、global/host/admission 可用量、generation 与 stop 状态即可；不记录命令、密钥或文件内容，不在关键锁内同步写日志。保持原期限与零自动重试，先由最后阶段决定是否需要更细探针。

## 读取的主要源码

- `hepta-runtime/src/mcp/runtime/ssh_observation_pool.rs`
- `hepta-runtime/src/mcp/runtime/ssh_observation_profile.rs`
- `hepta-runtime/src/mcp/runtime/ssh_observation_validation.rs`
- `hepta-runtime/src/mcp/runtime/ssh_observation_postspawn.rs`
- `hepta-runtime/src/mcp/runtime/ssh.rs`
- `hepta-runtime/src/mcp/runtime/jobs.rs`
- `hepta-runtime/src/mcp/server.rs`
- `hepta-runtime/src/mcp/runtime/request_audit_trace.rs`
- `hepta-runtime/tools/x230/20261028/x230_observation_benchmark.py`
- `hepta-runtime/tools/x230/20261028/pinned_native_protocol.py`
