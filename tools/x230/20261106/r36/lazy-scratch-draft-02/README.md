# R36 草稿 02：局部懒初始化 scratch 与 reference 分支的哈希状态

**状态：仅静态候选，未格式化、未编译、未测试、未部署、未采用。** 等待 D2 实际成本后，再由 root 决定是否进入既有完整资格和性能门槛；本包没有收益结论。

基线严格为接受的 R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`，不是 D2。只改 `ssh_observation_profile.rs` 与原 sibling `ssh_observation_reference_tests.rs`，完整编译输入保持 220→220、仅两项 SHA 变化，其余 218 项保持基线。没有 Cargo、pool、validation、进程、队列、取消 helper 或任何门槛改动。

## 最小实现

### 1. reference=Some 时不构造未使用的 Context

`hash` 使用 `self.reference.is_none().then(|| Context::new(SHA256))`。函数期间 `self` 不可变，因此：

- reference=Some 时只做原参考比较，hash=None；
- reference=None 时 hash=Some，原每块 SHA update 及末端 finish 全部执行，空文件也完成空内容哈希。

原 reference 累积仍是非短路 `&=`。首块不匹配不会跳过后续读取、取消检查、最后的 FD/path fence。最终内容比较仍在原 `verify_read` 之后。生产代码没有新增 unwrap、expect、unsafe、panic 或可达提前返回。不可达的 None-hash/None-reference 组合不会被当作通过。

这只是在源码层面避免未用 Context 初始化；没有证明它涉及堆分配，也没有检查 LLVM 是否已经消除了该工作。

### 2. 一次 checked sweep 的独占懒 scratch

新增内部 `verify_checked_with_buffer` 接受 `&mut Option<[u8; 16384]>`。standalone wrapper 和每次 `Profile::verify_files_checked` 各自持有一个初始为 None 的局部 Option。

数组构造位置保留在原来的 `[0; VERIFY_BUFFER_BYTES]` 语句位置：

```text
initial check_current
→ fresh checked_file
→ post-open check_current
→ 固定 Stamp 比较
→ 条件 Context / matches_reference 初始化
→ buffer.get_or_insert_with(|| [0; VERIFY_BUFFER_BYTES])
→ 原 reader / 完整 read loop
```

因此未通过首次取消检查、open、第二次检查或 Stamp 的路径，不会先构造数组。第一次需要 buffer 时才初始化；后续五个 files/shell.target 调用按原顺序借用同一个已初始化数组。只有 returned count 内的 `buffer[..count]` 被比较或哈希；前一个文件留下的尾部不参与后一个文件的判断。

scratch 不跨 request、await、thread 或全局，不在 worker 与 owner 之间传递。worker 和 owner 的每次完整同步 sweep 分别创建自己的局部 Option，内容校验结果、FD、权限、permit、deadline 或终态均没有缓存/复用。原 `verify_files`、`verify_boundaries`、shell 和 policy 实现不改。

## 保留的行为

完整 fresh open、逐层 O_NOFOLLOW/O_NONBLOCK/O_CLOEXEC/目录规则、所有权/权限/capability、原2MiB reference预算和启动 pin 均不变。每文件保留原 `Read::take(maximum+1)`、相同16KiB读容量、Interrupted/EOF处理、所有 `check_current` 语句及其相对 I/O/错误判断的位置、最后 descriptor metadata 和 fresh path reopen，以及原错误优先级。

源比较核实原 per-file helper 中9处词法 `check_current()?;` 全部保留；这不是把动态回调总数预填为9，循环仍按每次读取执行原检查。候选的有限明确变换可精确逆回整份原 profile；删除新增测试块可精确恢复整份原 sibling tests。原 pool/validation/registry/reap/stop 代码不在 patch 中。

## 两项必要测试草稿

保持初稿的两项测试，只把 scratch 参数适配为 Option、初始值改成 None，没有增加测试范围：

1. `shared_verification_buffer_ignores_stale_tail_across_modes_and_lengths`：一块 scratch 按长→短→空→长→短→空读取多个独立真实私有文件，reference/SHA交替并交换起始模式。第一长文件填满 scratch，后续短尾/空读取保留旧尾。结果与回调次数对照 standalone fresh verification。
2. `shared_verification_buffer_keeps_mismatch_cancellation_precedence`：先用另一个长文件填 scratch，再验证首字节被修改的文件。reference 与 SHA 都必须读到原最终 fence；在每个原回调位置注入取消，保持原取消错误优先级及调用数。

现有多块/尾块/空文件、reference pin/budget、首块 mismatch 后继续检查、路径/metadata/长度错误顺序，以及 worker 接受后 owner 仍检出内容变化的原测试，正文全部未改。以上测试均未执行，原测试覆盖不能冒称本候选已通过。

## 原初稿与本次差分

初稿在 wrapper/sweep 入口提前构造数组，会给已过期早退路径增加初始化。root 因取消吞吐契约要求，选择本次 lazy 修订，保持原首次检查/open/stamp-before-init顺序。

- 原 eager 草稿完整保全：catalog `6222cee18e3a2f1152371fc63530d450724e2fd0`，11项198854 B。
- `initial-to-lazy.patch` 只改两个局部初始 None、内部 Option参数、原位置 get_or_insert_with 及两测试的对应类型/初始值。
- `candidate.patch` 始终是 accepted R24→本 lazy 草稿的完整两文件 diff，不能与初稿 patch 累加应用。

## 仍需实际判断的成本

源码层面，一次六文件 checked sweep 最多只构造一次16KiB数组；不能据此声称实际减少80KiB写入或降低RSS。Rust/LLVM可能已做消除，Option判别、数组临时值/复制、内联和栈布局也可能抵消收益。懒 Option 的有效载荷安全初始化，不使用 MaybeUninit/unsafe，但同样未证明编译后的栈或指令成本更小。

D2 的 Context/原 buffer 初始化属于细分 read-loop span 外的同步余量；完整 ReadReference/ReadHash 包含必须保留的读取、比较/哈希和取消检查。不能把这些整段成本当作本补丁可回收成本。R33路径缓存和R35分配/command移动的拒绝记录不被本稿覆盖，也不重新归因。

若 D2 没有显示足够大的相关预算，可以保留本稿而不进入昂贵全量资格；若继续，仍需原有测试、生命周期/并发取消和性能门槛，不能靠静态变化或组件结果采用。

## 文件与来源

- `source/`：两个完整候选文件；`baseline/`：两个精确 R24 原件。
- `baseline-source-map.json` / `candidate-source-map.json`：完整220项图。
- `input.json`：来源、两文件身份、两项新增测试名、完整图和patch身份；资格/CI/性能结果均为 null，adopted=false。
- `static-review.json`：作者的纯源码字节/数据流复核，明确不等价 Rust 编译或测试。
- 设计原件：Git `ff2b6e0ea76447d2b93ec5e5449f26c51379679f`。
- 基线220图来自 Git `86c91524ab994accb647e900220361b2505e31ba` 的 `baseline_compile_inputs`；该旧R33输入只作R24图的载体，没有混入R33源码。两处原源已按 accepted commit 独立取得并与图一致。

本轮仅本地元数据/字节对照和 Git blobs；没有 host API、Cargo、rustfmt、Rust测试、fixture运行、工作负载或审计器调用，也没有 Git tree/commit/ref 修改。
