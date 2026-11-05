# X230 优化 R15：固定 R14 代码，验证 glibc arena1 执行配置

日期：2026-11-03 UTC。状态：R15 配置资格、两组本地性能、两组 native 性能、六机恢复以及三份独立审计均已完成；本文是基于冻结证据定稿的发布报告。推荐把 arena1 作为本次已测 X230/glibc 环境的可选启动配置。本轮没有新的 Rust 修改或编译。

## 结论与取舍

同一个已资格 R14 二进制，加入 MALLOC_ARENA_MAX=1 后，4,194,272 字节 escaped receipt 的 VmHWM 中位数在 workers=1/2 下分别从 106,338/102,650 KiB 降到 29,070/30,720 KiB（−72.66%/−70.07%），结束时 RSS 从 106,338/102,650 KiB 降到 22,838/19,196 KiB（−78.52%/−81.30%）。

这个内存收益带有明确成本。同一二进制下，大 receipt 的 mixed RPC rate 为 +0.48%/−3.75%，CPU/RPC 为 −1.88%/+2.60%，host_list p95 为 +35.84%/+22.23%；小 receipt workers=1 的 CPU/RPC +6.49%、rate −6.03%。因此不能把 R15 写成所有指标同时提升。

R11→最终配置是代码与配置的合并结果：大 receipt workers=1 的 rate +68.62%、host_list p95 −91.88%，但 CPU/RPC +11.20%、VmHWM +32.83%、RSS-after +41.43%；workers=2 的 rate −6.33%、CPU/RPC +6.85%、host_list p95 −82.29%，VmHWM −10.32% 而 RSS-after +6.34%。小 receipt workers=2 出现 89.2773 ms 的 host_list p99 和 87.3614 ms 的 cancel p99，分别比该 R11 对照高 244.84%/266.97%，完整保留。

native 同二进制 C8 的 rate −1.11%、CPU/call +0.87%、p95 +2.92%、p99 +9.13%；两次 B 的 rate 和 CPU 都处于两次 A 的观测范围内。R11→最终 C8 的 rate +2.18%、CPU/call −2.71%、p95 −0.91%、p99 −5.93%。这些有限样本没有给出需要立即扩大 arena2 矩阵的明确额外争用证据，尾延迟负向仍须按实际 SLO 判断。

## 代码、二进制与配置绑定

R15 直接复用 R14 已冻结的 219 个编译输入、3 个 release 产物和 5 个 retained test executables。独立资格审计重新核对测试时、资格结束时和当前源码完全相同。R15 编译调用为 0，Rust 源码修改为 false。

| 绑定对象 | SHA256 |
| --- | --- |
| R14 source-map.json（219 项） | d24d2cc040c3f3d9849112e55a076834d06d12a65ec647987c5e419c3621354c |
| R14 implementation-ready.json | efdc0a817aa4a9b80106a31b899678a4b7863523dd47e145f99b5d6ee2aa6442 |
| R14 qualification report | d6a46164b30c6677cf49ec7eea156748a8445589c71034795d016a62795610cd |
| R15 baseline-binding.json | d701ad5c2d101ed389614083b386324c092182dcf19cb4f4bf0777e232d3c37a |
| src/mcp/runtime/jobs.rs | 694a4e4dcbc2be499879abd837f0b5e399f9cad95caab34716907de15cbbe82f |
| hepta-runtime | 51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d |
| hepta-runtime-jobctl | 84572095b80a56ff893ea41b01e170444dc2483a49091277d0b4ada4fbc1c1b0 |
| native_process_driver | 551aa5ba0f990908d0143c34f513a0f1937f14198335c5e4a611a112b82f944e |
| R11 baseline hepta-runtime | 660d64674fe3422006c0c2a82bc31f3f36edf19baf6613df7cdce51e8f3f8e4c |
| configuration/hepta-runtime-x230-glibc.sh | 7814b30921098756eb97624ee93876b538b11ce5dc3093dc52bd0e6c9335b525 |
| configuration/allocator-policy.json | 2f0ba167b73ea00b684d0f0f56f6e8d66832bd6bd72db848d89b6c8ca646a3ac |
| configuration/configuration-ready.json | fb4a2e8eab0bfafb0c272c4c3e259cd1d68dffbaa479796854a73a1100fcc947 |


继承的 R14 取消路径仍有 8 个 publication slots 与独立 2 个 preparation permits。两个 permit 在异步侧取得后一起移入 spawn_blocking；prep 覆盖实际 prepare+append，随着真实闭包退出释放，不延伸到 remote/completion。已提交队列工作在调用者取消后仍保有实际工作与 guard 的所有权；尚未提交的等待者被取消时释放已持有的 publication slot。prep=2 限制大分配的物理准备并行，不把后续远端 continuation 限制成 2。

## 资格与环境可归因性

| 检查 | 已验证结果 |
| --- | --- |
| 隔离测试 | 1,637 passed / 0 failed / 33 ignored / 1,670 selected；0 retries；身份与状态相对 R14 未改变 |
| 真实子进程 allocator 环境 | 1,647 verified / 0 unavailable_process_exited |
| wrapper 自检 | 15 项；包含继承、冲突、空值、精确 tunable 匹配、参数/PID 保留、stdout 安静及错误退出 |
| loader 实测 | 3 项 fresh loader 观察；glibc 2.39 的 GLIBC_TUNABLES arena key 优先于 MALLOC_ARENA_MAX |
| driver 环境自检 | 7 项；最小环境清理及记录/核验逻辑 |
| performance 环境绑定 | 32 个 cancel + 16 个 native generation，共 48 个实际 PID/start 绑定 |
| recovery 环境绑定 | 3 个 controller generation 的实际环境均验证 |


正式性能 driver 对基线和候选都先清除全部 MALLOC_* 与 GLIBC_TUNABLES。A 保持 clean default，B 显式只注入 MALLOC_ARENA_MAX=1；以 binary SHA256 + allocator environment 生成 configuration fingerprint，并在 initialize 后读取 /proc/PID/environ，同时绑定 PID/start ticks 防止误读 PID 复用。native 每轮初始与 restart 都验证，4 轮合计 8 次；恢复 3 次 controller 启动均验证。held SSH-agent 身份保持不变，未更改远端 workload 环境或全局服务配置。

隔离测试包含多个不同 executable，顶层 allocator metadata 的 binary_sha256 为 null；它本身不能充当单一二进制绑定。独立审计通过 inventory、每条精确测试命令与其 executable SHA、测试前后哈希完成逐产物绑定。短命进程若已经退出只能记 unavailable_process_exited，不能冒充 live 环境验证或重跑以获得快照；本次实际为 0 unavailable。

保留的关键并发测试：

- mcp::runtime::jobs::cancel_io_tests::cancelled_intent_writers_retain_two_physical_preparation_slots
- mcp::runtime::jobs::cancel_read_tests::cancelled_receipt_preparations_keep_two_physical_slots_and_release_unsubmitted_waiters
- mcp::runtime::jobs::cancel_read_tests::two_preparation_slots_preserve_eight_publication_continuations

## 为什么选择 arena1

R14 prep=2 解决了大准备工作的 CPU 并发放大，却不保证所有大分配只落到两个永久线程。独立诊断使用同一个 qualified R14 runtime，观察到各设置均约 19–20 个线程峰值、idle 后 10 个线程；glibc 默认配置下的大量保留映射与线程退出后 RSS 不回落相符。

两组限定诊断的顺序为 default/2/2/default 和 1/4/4/1，每个 fresh child 为 2 warmup waves + 24 measured waves + 12 s idle。诊断每个 child 的 234 次混合 RPC 包含 warmup；CPU 区间是 ready→warmup+load 完成，不能与正式排除 warmup 的 CPU/RPC 混用。后台证据归档 I/O 可重叠，所以没有诊断吞吐结论。

| 诊断设置 | CPU 秒均值（2 个 child） | 整 child HWM KiB 均值 | 12 s idle RSS KiB 均值 |
| --- | --- | --- | --- |
| default | 6.225 | 102,028 | 102,028 |
| arena1 | 6.315 | 30,788 | 17,244 |
| arena2 | 6.375 | 39,014 | 17,476 |
| arena4 | 6.340 | 52,988 | 36,424 |


arena1 的诊断 HWM 最低、idle RSS 与 arena2 接近；跨 campaign CPU 均值仅描述方向，其中 arena1 相对 default +1.45% 仍保留。smaps 中的 64 MiB 保留映射形状只是 allocator arena 的启发式线索，不能当作直接枚举 malloc arena。诊断独立汇总核验 1,872 条完整响应和 24 个 smaps 文件，SHA 为 053996e41ebb0b29d9e76f92ed381bb7af0c9db5a22298ae2d92cb6803586020。正式 R15 ABBA 才提供以下配置对照。

## 性能 CPU 计量范围

表内 CPU/call 来自 measured 区间两端、同一 PID/start generation 的 /proc/PID/stat utime+stime 差值；它只计 controller 自身，不包括 SSH 子进程、远端 workload 或全机群 CPU。采样进程树的计数存在异步采样、短命进程遗漏及生命周期差异，不用于性能 CPU 分子，也不把其差值声称为完整执行 CPU 的严格下界。native 测量操作为 process_status/process_read，不能当作新任务启动、process_wait 或成功取消吞吐。

## 完整正式性能表
### 表格来源

本文件直接从冻结的 performance-report-data.json 格式化；不重新运行测量或原分析器。所有显示值都只在最后一步四舍五入，完整精度以 JSON 为准。

数据 SHA256：e8203c3477de1ebeb353dfa74affc2bbc65090d33477b74c7852a39ae0f2f2b2。独立审计 SHA256：3a3724e5a1cfbd4daade73d68ad96f2e97aad71f47a2f948fb8d1669cacfe4db。

## 比较、分母与范围

A/B 为每个实验自己的基线/候选，执行顺序为 ABBA，各臂两个新进程。R14 对照使用完全相同的已资格二进制；R11 对照同时包含代码与配置差异。不同 campaign 的结果不相加、不相乘、不混池。

每个 cancel campaign 共 16 个 controller、3,456 次 measured RPC、288 次 warmup RPC。每个 worker/receipt 场景、每一臂汇总 432 次 measured RPC（384 次预期的 wrong-host cancel 拒绝 + 48 次 host_list）。CPU ms/RPC = 两进程 measured CPU 秒之和 × 1000 / 432；RPC/s = 432 / 两进程 measured wall 秒之和。warmup 不进入这两个分母。

大 receipt 精确为 4,194,272 字节，小 receipt 为 1,024 字节。cancel fixture 走完整验证和预期拒绝入口，但不 append 成功取消意图、不执行远端取消，因此不能把该速率称为成功取消吞吐。

分位数对单个 campaign、场景、臂和工具的原始 measured 延迟合并后取 nearest rank ceil(p×N)，不是平均各进程 p95。host_list N=48，p95 为第 46 个，p99 为第 48 个（最大值）；cancel N=384，p95 为第 365 个，p99 为第 381 个。

VmHWM 是整个 child 自 exec 起的高水位，包含初始化和 warmup；RSS-before/after 是 measured 前后的点采样，RSS-after 不代表 idle 后或峰值。下表中位数来自两个新进程，样本对同时保留。

每个 native campaign 共 1,152 次 measured、288 次 warmup、72 次 preflight/restart 验证，合计 1,512 次。每个 C/臂为两个 first-controller 各 96 次 measured，共 N=192；p95 为第 183 个，p99 为第 191 个。CPU 与速率同样用 pooled 分子和 wall 分母。四次 first-controller 和四次 restart 共 8 次 live 环境观察。

所有 Δ 是 (B/A−1)×100%。速率变大为有利方向，CPU、延迟及内存变小为有利方向；仅两个进程/臂，不宣称统计显著性。

## Cancel：R14 default → R14 + arena1（同一二进制）

A = clean allocator default；B = 仅注入 MALLOC_ARENA_MAX=1。每行/臂为上述 432 次 measured RPC。

### CPU 与混合 RPC 速率

| 场景 | A CPU ms/RPC | B CPU ms/RPC | Δ B/A | A RPC/s | B RPC/s | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| w1; 1,024 B | 1.7824 | 1.8981 | +6.49% | 555.1463 | 521.6700 | -6.03% |
| w1; 4,194,272 B | 25.8796 | 25.3935 | -1.88% | 76.4106 | 76.7791 | +0.48% |
| w2; 1,024 B | 1.8750 | 1.8519 | -1.23% | 537.0911 | 559.1538 | +4.11% |
| w2; 4,194,272 B | 25.8565 | 26.5278 | +2.60% | 76.4299 | 73.5645 | -3.75% |


### host_list 尾延迟（ms；N=48/臂，p99=max）

| 场景 | A p95 ms | B p95 ms | Δ B/A | A p99 ms | B p99 ms | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| w1; 1,024 B | 17.8829 | 18.4195 | +3.00% | 18.5182 | 18.6603 | +0.77% |
| w1; 4,194,272 B | 20.3501 | 27.6439 | +35.84% | 28.8781 | 39.5435 | +36.93% |
| w2; 1,024 B | 20.4061 | 17.1317 | -16.05% | 24.2532 | 17.3926 | -28.29% |
| w2; 4,194,272 B | 17.3823 | 21.2462 | +22.23% | 20.6864 | 23.3010 | +12.64% |


### cancel 拒绝尾延迟（ms；N=384/臂）

| 场景 | A p95 ms | B p95 ms | Δ B/A | A p99 ms | B p99 ms | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| w1; 1,024 B | 17.0334 | 18.8441 | +10.63% | 17.6002 | 22.0006 | +25.00% |
| w1; 4,194,272 B | 124.1852 | 129.6644 | +4.41% | 135.1272 | 148.1855 | +9.66% |
| w2; 1,024 B | 18.9931 | 15.8589 | -16.50% | 22.8699 | 16.5419 | -27.67% |
| w2; 4,194,272 B | 121.7422 | 126.6836 | +4.06% | 143.4026 | 146.0124 | +1.82% |


### 整 child 内存中位数（KiB；2 个进程/臂）

| 场景 | A VmHWM KiB | B VmHWM KiB | Δ B/A | A RSS-after KiB | B RSS-after KiB | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| w1; 1,024 B | 14,438 | 13,690 | -5.18% | 14,438 | 13,690 | -5.18% |
| w1; 4,194,272 B | 106,338 | 29,070 | -72.66% | 106,338 | 22,838 | -78.52% |
| w2; 1,024 B | 15,450 | 15,014 | -2.82% | 15,450 | 15,014 | -2.82% |
| w2; 4,194,272 B | 102,650 | 30,720 | -70.07% | 102,650 | 19,196 | -81.30% |


### 内存样本对与计算分子

| 场景 | 臂 | VmHWM 样本 KiB | RSS-before 样本 KiB | RSS-after 样本 KiB | CPU 合计 s | wall 合计 s |
| --- | --- | --- | --- | --- | --- | --- |
| w1; 1,024 B | A | 14,224 / 14,652 | 13,616 / 13,828 | 14,224 / 14,652 | 0.770000 | 0.778173302 |
| w1; 1,024 B | B | 13,688 / 13,692 | 13,288 / 13,268 | 13,688 / 13,692 | 0.820000 | 0.828109673 |
| w1; 4,194,272 B | A | 114,652 / 98,024 | 75,956 / 64,192 | 114,652 / 98,024 | 11.180000 | 5.653662167 |
| w1; 4,194,272 B | B | 29,472 / 28,668 | 27,372 / 13,416 | 27,712 / 17,964 | 10.970000 | 5.626528634 |
| w2; 1,024 B | A | 15,420 / 15,480 | 14,548 / 14,700 | 15,420 / 15,480 | 0.810000 | 0.804332764 |
| w2; 1,024 B | B | 15,252 / 14,776 | 14,608 / 14,324 | 15,252 / 14,776 | 0.800000 | 0.772596075 |
| w2; 4,194,272 B | A | 103,324 / 101,976 | 72,528 / 64,088 | 103,324 / 101,976 | 11.170000 | 5.652236161 |
| w2; 4,194,272 B | B | 31,184 / 30,256 | 14,760 / 19,412 | 19,188 / 19,204 | 11.460000 | 5.872393826 |


## Cancel：R11 default → R14 + arena1（代码与配置合并）

A = clean allocator default；B = 仅注入 MALLOC_ARENA_MAX=1。每行/臂为上述 432 次 measured RPC。

### CPU 与混合 RPC 速率

| 场景 | A CPU ms/RPC | B CPU ms/RPC | Δ B/A | A RPC/s | B RPC/s | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| w1; 1,024 B | 1.7824 | 1.8287 | +2.60% | 550.7310 | 529.6362 | -3.83% |
| w1; 4,194,272 B | 23.3565 | 25.9722 | +11.20% | 44.9117 | 75.7324 | +68.62% |
| w2; 1,024 B | 1.8519 | 1.9213 | +3.75% | 533.6027 | 506.5733 | -5.07% |
| w2; 4,194,272 B | 25.0231 | 26.7361 | +6.85% | 78.3127 | 73.3589 | -6.33% |


### host_list 尾延迟（ms；N=48/臂，p99=max）

| 场景 | A p95 ms | B p95 ms | Δ B/A | A p99 ms | B p99 ms | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| w1; 1,024 B | 18.1730 | 19.4960 | +7.28% | 18.8973 | 28.6705 | +51.72% |
| w1; 4,194,272 B | 213.2146 | 17.3139 | -91.88% | 221.9371 | 17.9479 | -91.91% |
| w2; 1,024 B | 18.7582 | 17.0649 | -9.03% | 25.8898 | 89.2773 | +244.84% |
| w2; 4,194,272 B | 123.0999 | 21.7981 | -82.29% | 134.9166 | 28.8743 | -78.60% |


### cancel 拒绝尾延迟（ms；N=384/臂）

| 场景 | A p95 ms | B p95 ms | Δ B/A | A p99 ms | B p99 ms | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| w1; 1,024 B | 17.6342 | 18.9134 | +7.25% | 18.7759 | 28.1894 | +50.14% |
| w1; 4,194,272 B | 212.7872 | 124.1908 | -41.64% | 218.4529 | 140.5657 | -35.65% |
| w2; 1,024 B | 17.4097 | 15.7626 | -9.46% | 23.8062 | 87.3614 | +266.97% |
| w2; 4,194,272 B | 122.3350 | 130.0567 | +6.31% | 132.6716 | 146.0314 | +10.07% |


### 整 child 内存中位数（KiB；2 个进程/臂）

| 场景 | A VmHWM KiB | B VmHWM KiB | Δ B/A | A RSS-after KiB | B RSS-after KiB | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| w1; 1,024 B | 14,070 | 13,964 | -0.75% | 14,070 | 13,952 | -0.84% |
| w1; 4,194,272 B | 22,044 | 29,280 | +32.83% | 14,148 | 20,010 | +41.43% |
| w2; 1,024 B | 15,374 | 14,980 | -2.56% | 15,374 | 14,980 | -2.56% |
| w2; 4,194,272 B | 34,248 | 30,712 | -10.32% | 18,670 | 19,854 | +6.34% |


### 内存样本对与计算分子

| 场景 | 臂 | VmHWM 样本 KiB | RSS-before 样本 KiB | RSS-after 样本 KiB | CPU 合计 s | wall 合计 s |
| --- | --- | --- | --- | --- | --- | --- |
| w1; 1,024 B | A | 13,996 / 14,144 | 13,448 / 13,680 | 13,996 / 14,144 | 0.770000 | 0.784412019 |
| w1; 1,024 B | B | 13,944 / 13,984 | 13,448 / 13,540 | 13,936 / 13,968 | 0.790000 | 0.815654208 |
| w1; 4,194,272 B | A | 21,972 / 22,116 | 13,720 / 13,812 | 14,100 / 14,196 | 10.090000 | 9.618868085 |
| w1; 4,194,272 B | B | 29,908 / 28,652 | 17,892 / 13,492 | 22,020 / 18,000 | 11.220000 | 5.704295954 |
| w2; 1,024 B | A | 15,208 / 15,540 | 14,624 / 14,948 | 15,208 / 15,540 | 0.800000 | 0.809591053 |
| w2; 1,024 B | B | 14,908 / 15,052 | 14,480 / 14,468 | 14,908 / 15,052 | 0.830000 | 0.852788777 |
| w2; 4,194,272 B | A | 34,896 / 33,600 | 15,328 / 15,072 | 21,816 / 15,524 | 10.810000 | 5.516349566 |
| w2; 4,194,272 B | B | 30,764 / 30,660 | 14,812 / 14,676 | 19,900 / 19,808 | 11.550000 | 5.888859140 |


## Native：R14 default → R14 + arena1（同一二进制）

A = clean allocator default；B = MALLOC_ARENA_MAX=1。每行 C/臂为 192 次 measured native status/read 调用；不含 warmup 和 preflight/restart。

| 场景 | A CPU ms/call | B CPU ms/call | Δ B/A | A calls/s | B calls/s | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| C1 | 129.5312 | 129.0625 | -0.36% | 4.3922 | 4.3244 | -1.54% |
| C4 | 73.0729 | 72.3438 | -1.00% | 17.5215 | 18.2721 | +4.28% |
| C8 | 72.1875 | 72.8125 | +0.87% | 23.1270 | 22.8705 | -1.11% |


| 场景 | A p95 ms | B p95 ms | Δ B/A | A p99 ms | B p99 ms | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| C1 | 283.1398 | 288.4282 | +1.87% | 322.1659 | 333.0142 | +3.37% |
| C4 | 286.8169 | 277.1265 | -3.38% | 315.5807 | 307.6004 | -2.53% |
| C8 | 415.0944 | 427.2079 | +2.92% | 436.8014 | 476.6841 | +9.13% |


### Native controller 内存范围（KiB）

first-controller 的内存覆盖 preflight、全部 C1/C4/C8 和 warmup，不可归属于某一个 C。restart-controller 是另一组进程，仅用于重启验证，单列。采样 RSS 峰值是采样下界；VmHWM 来自该进程状态。

| 范围 | 臂 | VmHWM 两样本 | VmHWM 中位数 | 采样 RSS-peak 两样本 | RSS-peak 中位数 |
| --- | --- | --- | --- | --- | --- |
| first-controller，全 C | A | 17,400 / 17,148 | 17,274 | 17,400 / 17,148 | 17,274 |
| first-controller，全 C | B | 16,412 / 16,936 | 16,674 | 16,412 / 16,936 | 16,674 |
| restart-controller | A | 15,336 / 14,896 | 15,116 | 15,336 / 14,896 | 15,116 |
| restart-controller | B | 15,020 / 14,764 | 14,892 | 15,020 / 14,764 | 14,892 |


| 范围 | VmHWM 中位数 Δ | RSS-peak 中位数 Δ |
| --- | --- | --- |
| first-controller，全 C | -3.47% | -3.47% |
| restart-controller | -1.48% | -1.48% |


### C8 两轮分布（每进程 96 次 measured）

| 臂 | 两轮 calls/s | 两轮 CPU ms/call | 两轮 p99 ms（N=96，均为本轮 max） |
| --- | --- | --- | --- |
| A | 22.613769 / 23.663974 | 73.645833 / 70.729167 | 470.9341 / 432.9463 |
| B | 23.050833 / 22.692881 | 72.812500 / 72.812500 | 463.6046 / 504.0235 |


资源采样保留的错误计数：{"fd:PermissionError": 14}。这些是原始 FD 采样权限错误，不能伪装为 FD=0；CPU/RSS 可用字段仍保留。tree RSS/FD 为非同时的部分进程和，采样 tree CPU 不作性能 CPU 分子。

## Native：R11 default → R14 + arena1（代码与配置合并）

A = clean allocator default；B = MALLOC_ARENA_MAX=1。每行 C/臂为 192 次 measured native status/read 调用；不含 warmup 和 preflight/restart。

| 场景 | A CPU ms/call | B CPU ms/call | Δ B/A | A calls/s | B calls/s | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| C1 | 130.3646 | 130.0000 | -0.28% | 4.3198 | 4.3131 | -0.16% |
| C4 | 71.9792 | 74.0625 | +2.89% | 18.3482 | 17.9786 | -2.01% |
| C8 | 72.9167 | 70.9375 | -2.71% | 22.9183 | 23.4182 | +2.18% |


| 场景 | A p95 ms | B p95 ms | Δ B/A | A p99 ms | B p99 ms | Δ B/A |
| --- | --- | --- | --- | --- | --- | --- |
| C1 | 286.1222 | 290.9553 | +1.69% | 318.1998 | 337.5060 | +6.07% |
| C4 | 284.1598 | 292.2664 | +2.85% | 341.6565 | 326.5765 | -4.41% |
| C8 | 415.2290 | 411.4441 | -0.91% | 451.9497 | 425.1509 | -5.93% |


### Native controller 内存范围（KiB）

first-controller 的内存覆盖 preflight、全部 C1/C4/C8 和 warmup，不可归属于某一个 C。restart-controller 是另一组进程，仅用于重启验证，单列。采样 RSS 峰值是采样下界；VmHWM 来自该进程状态。

| 范围 | 臂 | VmHWM 两样本 | VmHWM 中位数 | 采样 RSS-peak 两样本 | RSS-peak 中位数 |
| --- | --- | --- | --- | --- | --- |
| first-controller，全 C | A | 16,976 / 17,208 | 17,092 | 16,976 / 17,208 | 17,092 |
| first-controller，全 C | B | 16,556 / 16,832 | 16,694 | 16,556 / 16,832 | 16,694 |
| restart-controller | A | 15,080 / 15,484 | 15,282 | 15,080 / 15,484 | 15,282 |
| restart-controller | B | 14,712 / 14,740 | 14,726 | 14,712 / 14,740 | 14,726 |


| 范围 | VmHWM 中位数 Δ | RSS-peak 中位数 Δ |
| --- | --- | --- |
| first-controller，全 C | -2.33% | -2.33% |
| restart-controller | -3.64% | -3.64% |


### C8 两轮分布（每进程 96 次 measured）

| 臂 | 两轮 calls/s | 两轮 CPU ms/call | 两轮 p99 ms（N=96，均为本轮 max） |
| --- | --- | --- | --- |
| A | 23.127979 / 22.712292 | 72.500000 / 73.333333 | 442.8404 / 502.7699 |
| B | 23.478660 / 23.357996 | 70.625000 / 71.250000 | 438.6686 / 424.0460 |


资源采样保留的错误计数：{"fd:PermissionError": 15}。这些是原始 FD 采样权限错误，不能伪装为 FD=0；CPU/RSS 可用字段仍保留。tree RSS/FD 为非同时的部分进程和，采样 tree CPU 不作性能 CPU 分子。

## 全部方向性负面记录

以下 75 项完整来自独立审计的 negative_directional_results。它们是指标方向记录，不是 75 个独立故障；例如 host_list 的 p99 和 max 重复描述同一尾样本。没有丢弃 CPU/吞吐/尾延迟/内存的任何已列负方向，也没有把方向变化声明为统计显著。

| Campaign | 场景 | 指标（单位见字段名） | A | B | Δ B/A |
| --- | --- | --- | --- | --- | --- |
| cancel_r14_r15 | w1; 1,024 B | cpu_ms_per_mixed_rpc | 1.782407 | 1.898148 | +6.49% |
| cancel_r14_r15 | w1; 1,024 B | mixed_rpc_per_second | 555.146262 | 521.670033 | -6.03% |
| cancel_r14_r15 | w1; 1,024 B | host_list_p50_ms | 13.046986 | 14.159736 | +8.53% |
| cancel_r14_r15 | w1; 1,024 B | host_list_p95_ms | 17.882938 | 18.419504 | +3.00% |
| cancel_r14_r15 | w1; 1,024 B | host_list_p99_ms | 18.518240 | 18.660336 | +0.77% |
| cancel_r14_r15 | w1; 1,024 B | host_list_maximum_ms | 18.518240 | 18.660336 | +0.77% |
| cancel_r14_r15 | w1; 1,024 B | cancel_p50_ms | 14.183155 | 14.885684 | +4.95% |
| cancel_r14_r15 | w1; 1,024 B | cancel_p95_ms | 17.033398 | 18.844135 | +10.63% |
| cancel_r14_r15 | w1; 1,024 B | cancel_p99_ms | 17.600225 | 22.000629 | +25.00% |
| cancel_r14_r15 | w1; 1,024 B | cancel_maximum_ms | 17.772451 | 22.538761 | +26.82% |
| cancel_r14_r15 | w1; 4,194,272 B | host_list_p50_ms | 13.139277 | 13.609795 | +3.58% |
| cancel_r14_r15 | w1; 4,194,272 B | host_list_p95_ms | 20.350149 | 27.643933 | +35.84% |
| cancel_r14_r15 | w1; 4,194,272 B | host_list_p99_ms | 28.878050 | 39.543477 | +36.93% |
| cancel_r14_r15 | w1; 4,194,272 B | host_list_maximum_ms | 28.878050 | 39.543477 | +36.93% |
| cancel_r14_r15 | w1; 4,194,272 B | cancel_p95_ms | 124.185227 | 129.664408 | +4.41% |
| cancel_r14_r15 | w1; 4,194,272 B | cancel_p99_ms | 135.127240 | 148.185522 | +9.66% |
| cancel_r14_r15 | w1; 4,194,272 B | cancel_maximum_ms | 143.051676 | 163.261285 | +14.13% |
| cancel_r14_r15 | w2; 1,024 B | host_list_p50_ms | 15.616538 | 15.740165 | +0.79% |
| cancel_r14_r15 | w2; 1,024 B | cancel_p50_ms | 13.859863 | 14.144673 | +2.05% |
| cancel_r14_r15 | w2; 4,194,272 B | cpu_ms_per_mixed_rpc | 25.856481 | 26.527778 | +2.60% |
| cancel_r14_r15 | w2; 4,194,272 B | mixed_rpc_per_second | 76.429928 | 73.564548 | -3.75% |
| cancel_r14_r15 | w2; 4,194,272 B | host_list_p50_ms | 13.722808 | 14.049848 | +2.38% |
| cancel_r14_r15 | w2; 4,194,272 B | host_list_p95_ms | 17.382294 | 21.246225 | +22.23% |
| cancel_r14_r15 | w2; 4,194,272 B | host_list_p99_ms | 20.686430 | 23.301008 | +12.64% |
| cancel_r14_r15 | w2; 4,194,272 B | host_list_maximum_ms | 20.686430 | 23.301008 | +12.64% |
| cancel_r14_r15 | w2; 4,194,272 B | cancel_p50_ms | 75.196496 | 78.608395 | +4.54% |
| cancel_r14_r15 | w2; 4,194,272 B | cancel_p95_ms | 121.742232 | 126.683612 | +4.06% |
| cancel_r14_r15 | w2; 4,194,272 B | cancel_p99_ms | 143.402641 | 146.012424 | +1.82% |
| cancel_r14_r15 | w2; 4,194,272 B | cancel_maximum_ms | 149.719619 | 160.687207 | +7.33% |
| cancel_r11_r15 | w1; 1,024 B | cpu_ms_per_mixed_rpc | 1.782407 | 1.828704 | +2.60% |
| cancel_r11_r15 | w1; 1,024 B | mixed_rpc_per_second | 550.730980 | 529.636206 | -3.83% |
| cancel_r11_r15 | w1; 1,024 B | host_list_p95_ms | 18.173017 | 19.496013 | +7.28% |
| cancel_r11_r15 | w1; 1,024 B | host_list_p99_ms | 18.897290 | 28.670516 | +51.72% |
| cancel_r11_r15 | w1; 1,024 B | host_list_maximum_ms | 18.897290 | 28.670516 | +51.72% |
| cancel_r11_r15 | w1; 1,024 B | cancel_p50_ms | 14.177832 | 14.475246 | +2.10% |
| cancel_r11_r15 | w1; 1,024 B | cancel_p95_ms | 17.634223 | 18.913393 | +7.25% |
| cancel_r11_r15 | w1; 1,024 B | cancel_p99_ms | 18.775945 | 28.189412 | +50.14% |
| cancel_r11_r15 | w1; 1,024 B | cancel_maximum_ms | 18.970577 | 28.359216 | +49.49% |
| cancel_r11_r15 | w1; 4,194,272 B | cpu_ms_per_mixed_rpc | 23.356481 | 25.972222 | +11.20% |
| cancel_r11_r15 | w1; 4,194,272 B | vmhwm_kib_median | 22,044.000000 | 29,280.000000 | +32.83% |
| cancel_r11_r15 | w1; 4,194,272 B | vmrss_after_kib_median | 14,148.000000 | 20,010.000000 | +41.43% |
| cancel_r11_r15 | w1; 4,194,272 B | vmrss_before_kib_median | 13,766.000000 | 15,692.000000 | +13.99% |
| cancel_r11_r15 | w2; 1,024 B | cpu_ms_per_mixed_rpc | 1.851852 | 1.921296 | +3.75% |
| cancel_r11_r15 | w2; 1,024 B | mixed_rpc_per_second | 533.602735 | 506.573271 | -5.07% |
| cancel_r11_r15 | w2; 1,024 B | host_list_p99_ms | 25.889846 | 89.277333 | +244.84% |
| cancel_r11_r15 | w2; 1,024 B | host_list_maximum_ms | 25.889846 | 89.277333 | +244.84% |
| cancel_r11_r15 | w2; 1,024 B | cancel_p99_ms | 23.806202 | 87.361442 | +266.97% |
| cancel_r11_r15 | w2; 1,024 B | cancel_maximum_ms | 26.022617 | 87.648671 | +236.82% |
| cancel_r11_r15 | w2; 4,194,272 B | cpu_ms_per_mixed_rpc | 25.023148 | 26.736111 | +6.85% |
| cancel_r11_r15 | w2; 4,194,272 B | mixed_rpc_per_second | 78.312659 | 73.358861 | -6.33% |
| cancel_r11_r15 | w2; 4,194,272 B | cancel_p95_ms | 122.335048 | 130.056729 | +6.31% |
| cancel_r11_r15 | w2; 4,194,272 B | cancel_p99_ms | 132.671598 | 146.031438 | +10.07% |
| cancel_r11_r15 | w2; 4,194,272 B | cancel_maximum_ms | 140.044151 | 156.493988 | +11.75% |
| cancel_r11_r15 | w2; 4,194,272 B | vmrss_after_kib_median | 18,670.000000 | 19,854.000000 | +6.34% |
| native_r14_r15 | C1 | calls_per_second | 4.392229 | 4.324413 | -1.54% |
| native_r14_r15 | C1 | p50_ms | 223.490574 | 226.253027 | +1.24% |
| native_r14_r15 | C1 | p95_ms | 283.139791 | 288.428248 | +1.87% |
| native_r14_r15 | C1 | p99_ms | 322.165926 | 333.014211 | +3.37% |
| native_r14_r15 | C1 | max_ms | 323.702429 | 334.564879 | +3.36% |
| native_r14_r15 | C4 | max_ms | 319.479104 | 350.542177 | +9.72% |
| native_r14_r15 | C8 | cpu_ms_per_call | 72.187500 | 72.812500 | +0.87% |
| native_r14_r15 | C8 | calls_per_second | 23.126955 | 22.870456 | -1.11% |
| native_r14_r15 | C8 | p50_ms | 330.606396 | 336.475665 | +1.78% |
| native_r14_r15 | C8 | p95_ms | 415.094436 | 427.207877 | +2.92% |
| native_r14_r15 | C8 | p99_ms | 436.801393 | 476.684098 | +9.13% |
| native_r14_r15 | C8 | max_ms | 470.934066 | 504.023516 | +7.03% |
| native_r11_r15 | C1 | calls_per_second | 4.319789 | 4.313084 | -0.16% |
| native_r11_r15 | C1 | p95_ms | 286.122167 | 290.955256 | +1.69% |
| native_r11_r15 | C1 | p99_ms | 318.199785 | 337.505997 | +6.07% |
| native_r11_r15 | C1 | max_ms | 323.511683 | 363.080058 | +12.23% |
| native_r11_r15 | C4 | cpu_ms_per_call | 71.979167 | 74.062500 | +2.89% |
| native_r11_r15 | C4 | calls_per_second | 18.348183 | 17.978648 | -2.01% |
| native_r11_r15 | C4 | p50_ms | 206.231237 | 212.209255 | +2.90% |
| native_r11_r15 | C4 | p95_ms | 284.159798 | 292.266419 | +2.85% |
| native_r11_r15 | C4 | max_ms | 342.134101 | 370.283049 | +8.23% |


## 可独立验证的范围

独立复算核验 48 个唯一 PID/start generation，7,488 条完整 cancel 响应的原始哈希与语义，3,024 次 native 调用的已有哈希/DTO/count/状态。native observation 原报告没有保存完整 transport response envelope，因此完整 native envelope 独立重哈希数为 0。六机恢复使用另一套完整原始响应证据，不能借此补称 observation envelope 已验证。

原始 CPU/wall 差值和 latency 样本可检查、重算聚合，但原始单调时钟两端未完整保留，不能声称重新构建每个时钟区间。所有原始浮点值已检查 finite；两组负向数据和资源采样错误均保留。

## 多机、持久化与故障恢复

X230 controller 使用同一已资格 runtime + arena1，协调 ai395、mac、main、pocket4、rog、x230 六个受控主机完成恢复场景；远端 workload 环境未改变。独立恢复审计核验 90 个完整 native reply 文件、36 次 SSH probes 的 72 个 stdout/stderr 文件、150 个内嵌远端工件，共 224,885 字节内嵌内容，重算 6 个原始 controller record hash。12 次 cancel 调用、6 个新启动和 12 次 same-key lookup 均在原始证据内，自动 RPC 重试和额外 terminal polling 均为 0。

本轮受控故障为 SIGKILL 自己的 controller 与自己的 ROG SSH master，并确认 master generation 被替换；未修改网络或服务。恢复链保留 controller crash 后 running、transport 重建后 running、live concurrent cancel、terminal status/read、terminal 后重复 cancel、same-key reuse 以及再次重启后的 terminal 证据。六机 marker 证明这些 fixture 的一次执行，不能外推成任意分布式外部效果的 exactly-once 保证。

live successful cancel 实测最大重叠为 C6，六次调用启动时间跨度 2.0280 ms；这是六机活任务取消的重叠证据，不是成功取消 C8 的吞吐基准。Linux 的 cancel ACK 为 stop_requested，Mac 为 term_sent；ACK 中 termination_confirmed=false，单独的 ACK 不能证明已停止。终止结论来自后续 status、exit 与 witness 等终态证据。Linux 使用 pidfd；Mac 的身份检查为账户/PID-start best effort，边界仍保留。

R15 没有改变 intent append、fsync、receipt 验证、phase-boundary pin 内容重哈希、publication 所有权或重启恢复协议。release 的 panic=abort 不能用测试构建里的 unwind/JoinError 行为替代：本次 SIGKILL 恢复验证的是外部硬中断后的持久化状态，不能宣称测试了每个 panic 发生点。

本轮未做主机重启、真实断电、WAN partition、所有权迁移或外部业务效果去重实验，也没有因成功恢复而声称这些场景已获证明。

恢复验证完成后，独立核对所有权、inode、监听状态与进程 generation，仅清理本次崩溃 controller 遗留的 6 个私有 SSH sockets 和 2 个空目录；发送信号数为 0。清理记录 independent-audit-tools/socket-cleanup-01.json 的 SHA256 为 48557d7cb53f4501545742a4e33497dd7cfea2e596c2a37b63a5d4b710b58024。

## 配置使用与调用者覆盖

launcher 是 opt-in，只限定已测 X230/glibc 2.39 的证据范围。它检查 Linux/GNU libc 和绝对 executable 路径，然后 exec 原二进制；无后台 supervisor、无 stdout banner，错误写 stderr。它不逐次重新 hash 二进制，部署前的产物绑定由资格/launch gate 负责。

~~~sh
tools/x230/20261103/r15/configuration/hepta-runtime-x230-glibc.sh \
  /absolute/path/to/hepta-runtime mcp \
  --runtime-config /absolute/path/to/runtime-config.json
~~~

只有调用者未设置 MALLOC_ARENA_MAX、也没有精确的 colon-delimited glibc.malloc.arena_max= tunable 时，wrapper 才注入默认 1。显式 MALLOC_ARENA_MAX（包括空/无效值）原样保留；显式 arena tunable 阻止默认注入；其他 GLIBC_TUNABLES 原样保留并可与默认 1 共存。两种控制都存在时保留两者，由 loader 决定有效值。本机 fresh loader 证据显示 tunable 优先。该行为不修改登录环境、系统服务或远端配置。

~~~sh
MALLOC_ARENA_MAX=2 tools/x230/20261103/r15/configuration/hepta-runtime-x230-glibc.sh \
  /absolute/path/to/hepta-runtime mcp --runtime-config /absolute/path/to/runtime-config.json
~~~

上例是显式覆盖用法，不代表 arena2 已通过 R15 正式矩阵。正式 driver 直接 exec 相同二进制并设置 clean env，以避免 wrapper 的调用者继承策略污染配置归因；因此 caller override 后不能继续宣称与 arena1 对照环境相同。

configuration/README.md、configuration-ready.json、baseline-binding.json 以及 frontier-assessment-before-r15.json 中的 candidate/pending 状态是运行前冻结记录，保留历史原文与 SHA。当前资格结论来自本文件和终态三份独立审计，不能回改历史 ready 来伪造事前已资格。

## 本轮停止边界

本轮建议停止在 R14 prep=2/publication=8 + opt-in arena1。依据是已测大分配 RSS 保留显著降低，完整资格与六机恢复通过，且 native C8 未呈现明确额外 CPU/吞吐争用；这是有限证据下的工程选择，不是绝对最优或已证明的 Pareto 最优。

R14 先前的 R13 对照仍保留 CPU/RPC −30.83%/−28.14% 与 rate −14.33%/−19.45% 的交换，不能用 R15 内存收益掩盖。该大拒绝场景在 prep2 下 CPU/wall 约 1.968/1.956，之前约 3.321/3.380。X230 两物理核与四逻辑核并不证明 prep4 没有机会；SMT 或成功路径的 I/O/fsync overlap 可能受益，但本轮没有正式测 prep4。

继续 prep4 会增加同时的大 buffer、allocator/scheduler 竞争，并可能给回 CPU 和 host_list 响应性收益。已有 wrong-host fixture 未证明成功取消 I/O 是下一瓶颈，native status/read 又不取得 cancel preparation semaphore，不能把 prep4 当作修复 native C8 的直接手段。只有实际目标 workload 或明确 SLO 提供具体理由时，才应做定向实验。

arena2 也留作目标化选择：若其他分配模式出现可重复且跨两轮一致的额外 CPU/rate 成本，或明确尾延迟 SLO 失败，再做同二进制的限定比较。当前单个 p99 负向不足以证明锁争用，不能为了穷举参数扩矩阵。另一方面，当前尾延迟成本是真实观测，不能以样本有限为由删除。

| 尚未推进的优化 | 边界和原因 |
| --- | --- |
| 固定两条 preparation 专用线程 | arena1 已解决主要保留问题；新线程池增加交接、部分初始化、panic 传播、排队取消与 graceful shutdown 证明。外层保留 spawn_blocking 可维持 runtime 等待真实工作的语义，但仍多两层交接/等待线程，未实现、未测。 |
| 跨调用 pin 缓存或省略内容重哈希 | 会改变 phase-boundary 变更检测契约；metadata/inode/mtime 不能等价证明内容不变。 |
| 无分配 escaped JSON parser | 当前 ValidatedJobString 已用 Visitor 丢弃 decoded text；进一步移除 scratch/read buffer 需要独立的 Unicode、escape、错误与拒绝语义证据。 |
| 更深 remote snapshot 协议重写 | 需要新的 snapshot 一致性、恢复与故障协议，超出本轮低风险修改边界。 |
| 减弱 fsync、intent ownership 或把 ACK 当终止 | 不接受以变更持久化/取消契约来制造性能改善。 |


## 冻结证据与复算

下列相对路径以 R15 证据根目录为准；审计均顶层 success=true。表格直接由冻结 JSON 派生，原始测量、失败/负面方向、历史候选记录和审计工具一并留存。独立性能 auditor 只读取已完成结果，未运行新 workload；一次执行、0 automatic retries。

| 证据 | SHA256 |
| --- | --- |
| qualification-audit-summary.json | 5d99035bb3800fab4edcd7b21534d98f215f1a1411317999905677a81d5ae901 |
| independent-performance-audit.json | 3a3724e5a1cfbd4daade73d68ad96f2e97aad71f47a2f948fb8d1669cacfe4db |
| independent-recovery-audit.json | b276c885da5b821192ce454c6117c6fce6d7300df1164331d4d9c81b71ebbb5e |
| performance-report-data.json | e8203c3477de1ebeb353dfa74affc2bbc65090d33477b74c7852a39ae0f2f2b2 |
| independent-audit-tools/audit_performance_r15.py | df119841ab22fff91fe39f16e1916d501005767439b020aec27a05fd226607f7 |
| independent-audit-tools/performance-attempt-01/execution.json | d89a3f457b3bd98d2f8f96c84a5784fc76b79e9b3c83835dd465b52df2cf71d2 |
| independent-audit-tools/allocator-tooling-review.json | 8c87efb5b5aaa0e347bcc3f8beaa61d7c66d21011daf006550a41367b30f7cbb |
| configuration/wrapper-validation.json | 0d56f71802b5fe92e4188e2e9a4e3950afdb870e1fba8b93d9751c49d1657603 |
| configuration/loader-precedence.json | 2b21e5d5b00a2590b96a0a456764e3f4691822a456754284b8544cbd1090d1b0 |
| independent-audit-tools/environment-selftest-01.json | 0d82f2ee23f0bd5a8c92f431d7a403b413ca097b4ab0a7c53d392d15758f85fa |


原始证据包包含 20,798 个选定原始文件、92,473,514 字节原始内容；加上包内 manifest 共 20,799 个 tar members。打包后逐成员重算哈希、复查最终选择集，并核对 54 个 gate hashes 与 238 个 audited-input hashes。源代码、编译二进制和本发布报告不重复收入原始测量包。

| 发布文件 | 字节 | SHA256 |
| --- | ---: | --- |
| [r15-original-evidence-01.tar.gz](../tests/evidence/20261103-x230-r15/r15-original-evidence-01.tar.gz) | 5,949,022 | eb5b3bf2638406efa47543a45af5b1eff574b9db4a11e389c843d1a47d457b34 |
| [archive-selection-01.json.gz](../tests/evidence/20261103-x230-r15/archive-selection-01.json.gz) | 1,540,087 | 59a73076c0dc18c1ee091ac509c4bc32d364886b5adf30784e5dd5bfc8c79112 |
| [archive-summary-01.json](../tests/evidence/20261103-x230-r15/archive-summary-01.json) | 7,943 | 05907dadaf7a0dbc792187d773d4c0e1781478e910a1a2798bcde8d7b78cc009 |

包内原始记录与上述独立审计共同界定可复核范围；没有保存的 native observation 完整 envelopes 不因归档完成而补称存在。
