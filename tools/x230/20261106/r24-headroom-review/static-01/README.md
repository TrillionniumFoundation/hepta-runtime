# R24 下一轮静态热点筛选

## 结论

本轮保留 **两个可独立隔离的小候选**，优先顺序是：

1. `Core::arguments` 直接构造最终 SSH 参数，去掉固定选项的临时 owned key/value 容器。
2. `Core::spawn` 为完整 NUL 分隔 argv 证明字节预留准确容量，保留现有证明表示和比较路径。

第一项的浪费在源代码中最明确：每次构造普通 slave 参数都会对 30 组非空静态 key/value 调用 **60 次 `to_owned`**，之后再格式化为最终参数并丢弃这些临时字符串。第二项避免一个已知最终长度的字节向量依赖增量扩容，但其实际 realloc 数和收益必须先用当前工具链的组件计数确认。

两项都不会减少一次观测的 SSH slave / 远端 Python 进程数，也没有足够证据预测它们会改善约 20 ms/call 的整体 CPU 或约 55 rps 的六机吞吐。本轮没有找到能在保留原权限、期限和 owner 清理保证的前提下，直接删除一个进程、完整权限验证、必要文件同步或必需锁等待的可靠小改。没有为了凑满三个候选再提交另一个缺乏绝对收益证据的序列化改写。

**范围：只读源码、Git 历史与静态字节分析。没有运行 Rust、rustfmt、fixture、Cargo、benchmark 或任何 x230/Mac API；没有修改 R24、R35 或既有冻结包，没有创建 runtime patch。**

## 精确基线和调用链

源基线为接受的 R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`。

主要源文件：

- [`ssh_observation_pool.rs`](https://github.com/TrillionniumFoundation/hepta-runtime/blob/baab4def80be7af015b2e7a594cb302f66c4130e/src/mcp/runtime/ssh_observation_pool.rs)，Git blob `fe8096c1b6f0828d6745469b33ef92ea8b428bae`，63,329 B，SHA256 `92592431b6f4f0d3561c039ed86d9129f3942fb677ba9a336f639003b16b71d9`。
- [`ssh.rs`](https://github.com/TrillionniumFoundation/hepta-runtime/blob/baab4def80be7af015b2e7a594cb302f66c4130e/src/mcp/runtime/ssh.rs)：`prepare_observation` 260–344、`run_job_observation` 346–375。
- [`jobs.rs`](https://github.com/TrillionniumFoundation/hepta-runtime/blob/baab4def80be7af015b2e7a594cb302f66c4130e/src/mcp/runtime/jobs.rs)：`prepare_audit_at` 2305–2322、`observation_completion_audit` 2494–2509、status/wait/read 4421 起。

正常 pooled 请求在原有全部 admission / host / master / profile / socket / peer 检查后，进入 `execute_inner` 1510 的 `self.arguments(..., Mode::Slave, ..., false)`，1511 加入命令，再进入 `captured`。`captured` 987 起构造原 Command 并调用 `spawn`；`spawn` 870–873 生成完整 expected argv，再等待 children registry 锁和创建真实 Child。因此两个候选都位于每次普通观测的参数准备路径中，并非只在启动时运行的代码。

## 1. 优先：消除固定 SSH 选项的临时 owned key/value

### 原代码证据

`Core::arguments` 位于 `ssh_observation_pool.rs` **735–828**。函数先查询 host，建立最终 `Vec<String>`，然后：

1. 用 `vec!` 建立 30 个固定 `(&str, &str)` 选项对。
2. 对每个 key 和 value 执行 `to_owned`，收集成 `Vec<(String, String)>`。
3. 加入五个动态/模式选项。
4. 逐项生成 `"-o"` 和 `format!("{key}={value}")`，放入真正返回的参数向量。

30 组静态 key/value 均非空，共 60 次非空 String 构造，静态字面量合计 597 字节。这是源码级调用/字节计数，**不是已经测得的 allocator、CPU 或 RSS 数据**；编译器及分配器的实际行为仍以未来组件原始记录为准。额外的临时选项向量也没有进入返回值。

### 最小候选范围

仅改这个函数内部：对固定的借用选项数组逐项生成最终 `-o` / `key=value`，再按原顺序处理五个动态选项。动态路径可以继续使用原来的 `to_string_lossy().into_owned()` 表达式；无需引入新缓存、静态状态、借用到请求外部的对象或新的公共参数类型。

返回类型仍是 `Result<Vec<String>>`。参数内容与顺序必须逐字相同，包括：`/usr/bin/ssh`、`-F`、配置路径、可选 `-G`、`-T`、30 个固定选项、`IdentityAgent`、`UserKnownHostsFile`、`ControlPath`、`ControlMaster`、`ProxyCommand`、master 的 `-N/-n`、`--`、原 target。不能合并或重排选项，也不能改变 target 查找的首个错误位置。

`command`、`spawn`、post-exec argv 证明、PDEATHSIG、原 Child 注册、permit 保留、pidfd、超时/取消、未知 reap 保留和全部权限复核均不需要改变。Linux 模块范围不变。这与 R33 缓存路径组件不同：没有常驻新缓存，也没有复用 FD、inode、权限或校验结果。

### 历史覆盖

R25/R26/R28 和已读取的实际 R29 累计 patch 均未改这个 pool 文件。R27 serializer/compiler/router-cache 的 pool 快照保留同一个 R24 Git blob。此次又按固定 commit 读取 R30、R31、R33 的 pool，它们也都是 `fe8096…`。R34 的完整 220 map 只有 jobs/ssh/direct/direct_tests 四处差异，不包含 pool；R35 虽改 pool，但精确 diff 仅涉及 `execute` / `execute_inner` 的 command 所有权，没有改 `arguments`。因此该位置不属于已检索 R25–35 的现有改动。

这仍是对已保存 patch 和源快照的有限历史结论，不推断未发布私有草稿。

### 后续验证方案

先做很小的函数级组件，使用实际提取的原/新 `arguments`，同一组 Profile/host/path 输入，关闭记录阶段的计数干扰；统计成功路径 alloc/realloc/累计申请字节和 CPU/wall 原样本。预先固定 ABBA 顺序，保留每条原始值，不把组件结果称为全 runtime 收益。

语义回归需要验证四种 `Master/Slave × effective true/false` 的完整返回 argv 逐字相同，以及未知 host 的原错误。路径测试包含原允许的 Unicode 和重复分隔符；如果内部 fixture 人工构造非 UTF-8 Path，仍须保留原 lossy conversion 行为。保留原 SSH effective-config 和实际 owner/cancel/postspawn fixtures。若组件绝对节省极小，则按 R27 的绝对成本经验停止升级，不为减少几十次分配就预判吞吐提升；只有值得继续时才进入完整资格、精确 CI 与原六机门槛。

## 2. 次选：为 expected argv 证明字节准确预留容量

### 原代码证据

`Core::spawn` 的 **870–873**：

```rust
let expected = args
    .iter()
    .flat_map(|arg| arg.as_bytes().iter().copied().chain([0]))
    .collect::<Vec<_>>();
```

最终长度由当前已拥有的 args 完全决定：每项 UTF-8 字节长度加一个 NUL 的总和。当前代码没有显式按该总长度保留容量。该 iterator 的实际收集/扩容策略是工具链实现问题；此处不能仅从源码给出实际 realloc 次数。代码静态机会是把可确定的容量提供给向量，减少增量扩容可能带来的申请与复制。

### 最小候选范围与限制

在原来创建 expected 的同一位置，计算有界总长度，预留一次容量，再逐项追加原字节与 NUL。**继续生成完整 `Vec<u8>`**，保留 `postspawn::wait_empty_argv(..., &expected, ...)` 和 `value.argv == expected` 两处消费原样。不要把完整证明改成摘要、长度检查、前缀匹配或先前 Child 的缓存。

不改变 `children` 锁的取得、deadline 检查、进程创建、post-exec 等待或清理的先后顺序。长度处理必须不引入未检查的溢出；支持的真实输入来自原 profile 与 64 KiB command/input 限制，不能借容量预留放宽任何限制。该改动保留一个最终证明向量，最多减少扩容浪费，**不消除证明本身的拷贝或系统调用**。

### 历史与验证

这四行和 `arguments` 一样保留在上述 R24 pool 快照中；R35 也未改它。未来组件必须使用当前真实 Rust 工具链证明旧路径实际存在可避免的 realloc/申请字节，否则直接丢弃此候选。用真实普通 status/read 命令长度以及已允许的边界输入，比较完整 argv 字节、NUL 分隔和末尾 NUL，不只比长度或 hash。保留 empty-argv readiness、错误 argv/inode、deadline/cancellation、实际 child reap 的原测试。组件若有收益，仍不能推导原六机吞吐、CPU 或 RSS 已改善。

收益排序低于第一项：它需要额外长度扫描，旧 `collect` 的分配策略和 allocator 成本尚未量化。不要和第一项默默合并再把累计收益归给其中一个。

## 已排除或不作为下一候选的方向

### JobObservation 借用序列化已是 R27

此次取回 R27 `ssh.rs` Git blob `21bb4be7d92eede67f8b1037da400c24de94cfb8`，与 R24 的差异正是用 `JobObservationPayload<'a>` 直接借用序列化 status/read 等字段，移除中间 JSON Value。

原 [R27 README](https://github.com/TrillionniumFoundation/hepta-runtime/blob/08e0dabeab0c46bea91313e9e197bdb8d55d9d28/tools/x230/20261105/r27/README.md) 的实际结论是：组件改善已验证，但没有进入完整资格或六机接受，也没有采用。等权普通 status/read 准备阶段节省约 **0.61853 μs/call**，只相当于历史 R24 controller CPU/call 的约 **0.003201%**，该比例是量级对照，不是整体性能测量。不能把 R27写成“完整 runtime 性能失败”，也不能重复提案为新发现。

`jobs.rs::prepare_audit_at` 仍有另一处五字段 event JSON 中间值；理论上也可用借用序列化减少 map/key/outcome 复制，但它不是本轮推荐项。普通 observation 的 outcome 很小，采用相似机制需要再证明绝对成本值得，并保留 timestamp 标量转换、键序、JSON bytes、末尾 LF 和准备先于 backpressure 的语义。不能因为发现又一个 `json!` 就绕过 R27 已给出的量级教训。

### 已有缓存和安全边界

R24 `config.rs` 135–148 已把不可变 runtime policy digest 缓存在该 InstalledRuntimeConfig 自身的 OnceLock 中；不是每次 profile 检查都重新序列化完整配置。固定观测 Python command 也已在 `ssh.rs` 110–135 缓存。R35 处理的是未使用的 legacy read JSON 和 pool 中的一次 command clone；本轮不重复它们。

不减少完整 fresh profile 读取/校验、worker 后 owner 复核、agent 身份帧、socket/peer 证明或 audit 的 per-event sync。现有 validation permit 覆盖真实 worker 与 owner ticket；把排队移到一个无界线程/任务或提前归还 permit 也不属于安全优化。

### R30 router-only 不重复

原 [R30 README](https://github.com/TrillionniumFoundation/hepta-runtime/blob/7e3a08d549c60a66673b07c1d47e77fbe5c9df1c/tools/x230/20261105/r30/README.md) 和 [deadline 复核](https://github.com/TrillionniumFoundation/hepta-runtime/blob/7e3a08d549c60a66673b07c1d47e77fbe5c9df1c/tools/x230/20261105/r30/DEADLINE_REVIEW.md) 已取回保存。R30 在 R24 上单独缓存固定 ToolRouter；资格通过，原四轮六机观测有一条请求超时，因此未采用。外层 transport deadline 不能定位内部阶段，也不能证明 router 或环境导致该失败。本轮不再将相同 router 缓存包装为新候选，也不建议以重跑替换失败。

## 可复核原件

`findings.json` 保存候选、源文件/片段身份、静态计数、检索范围和执行边界。`baseline-fragments/` 只保存从原源码逐字截取的证据片段，不是新实现。`history/` 保留取回的 R27 原 source/README、实际 R29 patch、R30 README/deadline review；每件按原 Git blob 重新核算。R25/R26/R28 原 patch 另引自已封的 `r35-history-review-01`；R34/R35 原 freeze 未改变。
