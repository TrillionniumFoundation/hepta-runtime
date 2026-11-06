# R36 草稿 03：局部惰性 scratch 与 reference 分支的 Context

**仅静态源码准备：未格式化、未编译、未测试、未部署、未采用，没有收益结论。** 等待 D2 实际成本后，由 root 决定是否值得进入原全量资格和性能门槛。

基线为接受的 R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`。完整编译输入 220→220，仅 `ssh_observation_profile.rs` 与原 sibling `ssh_observation_reference_tests.rs` 两项变化，其余 218 项保持原图。没有 D1/D2 instrumentation、R31 pidfd、R33路径缓存、R34 reserve、R35 JSON/command 所有权改动，也没有 Cargo、pool、owner、队列或门槛修改。

## 两处源码变化

### 条件构造 SHA Context

`self.reference.is_none().then(|| Context::new(SHA256))` 只在没有不可变参考字节时构造 Context。reference=Some 对应 hash=None；reference=None 对应 hash=Some。函数内 `self` 不可变，两个模式不会切换。SHA 模式保留每块 update 和末端 finish，空文件也计算原空内容哈希。

参考比较仍使用非短路 `&=`。发现内容不匹配后继续完整读取、原取消检查和末端 descriptor/path fence；最终内容错误仍在原 `verify_read` 之后。没有 unwrap、expect、unsafe、新 panic 或可达提前成功分支；不存在的 hash 不会被当作通过。

这是源码层面避免未使用 Context 的构造，没有证明堆分配减少，也没有证明 LLVM 尚未消除这项工作。

### 同一同步 sweep 的独占惰性 scratch

standalone wrapper 和每次 `Profile::verify_files_checked` 分别拥有一个初始为 None 的 `Option<[u8; 16384]>`。新内部 helper 接收其独占可变借用，在原数组初始化位置调用：

```rust
let buffer = buffer.get_or_insert_with(new_verify_buffer);
```

私有 `new_verify_buffer` 只返回原完整初始化的零数组。它仅在 None 时被调用；后续同一 sweep 的五个 files 与 shell.target 顺序调用复用已初始化数组。scratch 不跨 request、await、thread、全局或 worker/owner 两次独立验证，也不缓存任何 FD、身份、内容验证结果、权限或 deadline。

第一次构造仍位于原顺序：

1. initial `check_current`；
2. fresh `checked_file`；
3. post-open `check_current`；
4. 固定 Stamp 比较；
5. 条件 Context 与 matches_reference 初始化；
6. 原 buffer 初始化位置；
7. 原 reader 和完整读循环。

因此源码不会给前四步拒绝的早取消/open/stamp 错误路径提前增加数组构造。实际机器码是否移动或消除此工作，仍未观察。

每次 read 接收完整16KiB可变切片，只比较/哈希 `buffer[..count]`。短文件或 EOF 留下的旧尾部不会参与后续判断。原 `Read::take(maximum+1)`、Interrupted/EOF、所有九处词法 `check_current()?;`、错误优先级、最后 metadata 和 fresh path reopen 保持。九处是词法位置，循环动态调用数没有预填为九。

## 最小测试草稿

只新增两个沿用原私有真实文件 fixture 的 sibling 测试；没有运行：

- `shared_verification_buffer_ignores_stale_tail_across_modes_and_lengths`：一块 scratch 依次处理长→短→空→长→短→空，reference/SHA 交替并交换起始模式，对照独立 fresh verification 的结果与回调次数。
- `shared_verification_buffer_keeps_mismatch_cancellation_precedence`：先用长文件填满 scratch，再验证首字节已变化的另一文件，分别覆盖 reference/SHA，并在各原回调位置注入取消，核对取消错误优先级与调用次数。

03 的整个测试文件与已审02逐字相同。删除新增测试块能精确还原整个 R24 sibling 文件；没有改写现有路径、元数据、内容、长度、worker 接受后 owner 再检查等测试。

## 修订链及静态检查

三份准备稿都保留：

| 准备稿 | 已保存 catalog | 处理 |
|---|---|---|
| 01 eager | `6222cee18e3a2f1152371fc63530d450724e2fd0` | 入口提前清零会改变早取消路径成本，未选作后续稿。 |
| 02 lazy closure | `386d2e2d4c39644cc0617193d8edf967160ba2d8` | 原位置惰性初始化正确，但静态检查发现官方 Rust 1.95 Clippy 对数组重复表达式的 unnecessary_lazy_evaluations 提示。 |
| 03 named lazy constructor | 本包 | 仅新增私有构造函数、将同位置 get_or_insert_with 参数改为函数 item。没有 lint allow、eager 初始化或新检查。 |

02 的发现来自官方 Clippy 源码静态审阅，**不是一次实际编译失败**。独立 finding 原件为 Git `832e9382912aeff847fbcc77be50899d014cc032`。官方该检查只进入闭包表达式分支，03 的函数 item 不进入该分支；实际全量 Clippy 仍未运行。

`draft02-to-draft03.patch` 是上述唯一命名构造器差异。反除该小差异逐字得到已审02 profile。02 的有限变换又可精确逆回整个 R24 profile；两个关系共同约束03没有额外生产改动。`candidate.patch` 始终为 **R24→03完整两文件补丁**，不要叠加应用旧补丁。

## 成本与采用边界

源码上每次六文件 checked sweep 最多构造一个16KiB数组；不能据此声称减少80KiB实际写入、堆分配、RSS 或 CPU。编译器可能已消除重复初始化；Option 判别、临时数组复制、函数内联和栈布局也可能抵消收益。

D2 read-loop span 外的同步余量包含原 Context/buffer 初始化，但还有其他工作。ReadReference/ReadHash 是完整 read+compare/hash+原 check_current 的组合成本，不能把整段预算视为本稿可回收成本。R33/R35 的原拒绝记录不被重释或覆盖。

本稿仅保存一个可审候选。继续资格必须遵守原测试、并发取消、生命周期及性能门槛；不能用静态变化、组件结果或诊断数据直接采用。

## 包内容与来源

`source/` 与 `baseline/` 各为两个完整源文件；两份 source-map 包含完整220项。input 包含相同基线、两文件身份、两测试名、完整图和补丁身份，qualification/exact_ci/performance 均 null，adopted=false。static-review 是作者字节/数据流复核，不能替代 Rust 编译与测试。

基线220图载体为 Git `86c91524ab994accb647e900220361b2505e31ba` 的 baseline_compile_inputs；只取其中的 R24 图，未混入 R33 源码。两处基线原件按 accepted commit 独立取得并与图一致。设计原件为 Git `ff2b6e0ea76447d2b93ec5e5449f26c51379679f`。

本轮仅本地源码/元数据字节处理及 Git blobs，没有 host、Cargo、rustfmt、Rust测试、fixture、工作负载、审计器执行或 Git tree/commit/ref 修改。
