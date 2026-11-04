# X230 R19：远端读取分配、CPU 与六机并发验收

R19 已通过全新构建的完整资格、六机 native observation、C32 突发及取消恢复验收，本轮选择采用这两处 Python 读取改动。采用依据是明确的组件 CPU／跟踪分配改善、故障路径 descriptor 清理修复，以及预先冻结的整链不回退筛选通过。

六个 X230 组件场景的 CPU 中位降幅为 23.17%–52.46%，小文件避免了按整个上限分配缓冲。整链主工作点 C8 的吞吐仅从 23.3520 变为 23.4021 调用/秒（+0.2143%），controller CPU/调用为 +0.0358%，p95 为 +0.7194%，p99 为 +1.9101%；主 controller HWM 的两次样本均值还增加了 104 KiB。本轮没有建立集群吞吐提高或稳定 RSS 下降的证据，不能将组件收益外推为同等幅度的整链收益。

## 被测对象与配置

本轮接续已接受的 R18，基线提交为 `a83fe08d736522cf01adee53902e3c13fbc1d5ae`。X230 上使用 R18 的有效 `qualification-02` 产物，而非此前被判无效的旧缓存资格。基线主 runtime SHA256 为 `51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d`，其实际字节与 R14 相同；jobctl 已包含 R18 的有界 BufReader 优化。

R19 只改变 `src/mcp/runtime/jobs.rs` 中两个嵌入式 Python 函数。最终源码 SHA256 为 `c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9`。从 GitHub 精确读取的父提交 `jobs.rs` 与 X230 的 R18 文件逐字节身份一致，SHA256 为 `694a4e4dcbc2be499879abd837f0b5e399f9cad95caab34716907de15cbbe82f`。其它源码、运行策略与原实验记录未被覆盖。

硬件为 ThinkPad X230，i5-3230M，2 个物理核、4 个硬件线程，约 7.46 GiB 内存，Linux 6.8.0-142，Rust 1.95.0。正式六机对照沿用 workers=2、`MALLOC_ARENA_MAX=1`，固定历史拓扑中的 ai395、mac、main、pocket4、rog、x230。该历史拓扑的 main 是独立 Linux 主机，不能用当前连接器的同名别名替换。

没有更改 governor、sysctl、全局服务配置或其它任务。组件 ABBA 与第一次完整构建在同一个独立 transient job 中执行，设置 nice=5、CPUQuota=200%、MemoryMax=5 GiB；第一次构建在组件测试结束后开始。第二次构建使用另一个独立 transient job 和新的空 target，其实际启动收据同样设置 nice=5、CPUQuota=200%、MemoryMax=5 GiB。完整资格结束、相关编译进程退出并经过固定 90 秒等待后，才启动六机测量。

## 代码为什么这样改

### 按实际大小分配读取缓冲

`private_read_json` 原来即使读取很小的 JSON，也调用 `read(4 MiB + 1)`。现在先读取至多 `max(0, st_size) + 1` 字节。如果实际返回的数据长度超过原始 `st_size`，再读取原预算中的剩余部分。这样普通稳定小文件避免了按整个上限申请缓冲。

保留最大返回字节预算、fresh open、owner/mode/nlink、读前/读后/当前命名路径的身份检查，以及原 JSON 解析契约。原私有 JSON 读取没有严格要求 `len == st_size`，本次也没有增加该条件。大小低报的特殊 regular file 仍可进入有界续读；续读返回 `None` 时保留已有前缀，不重试，不吞掉 `OSError`。首读 `None` 的 metadata 检查与错误顺序也保留。

`read_terminal_file` 原本已经强制最终字节数等于 fresh `st_size`，因此首读上限改为 `max(0, st_size) + 1`，多出的一个字节仍能检测增长。摘要、witness、nonce、job identity 与原有严格长度检查保留。

这些上限是返回／解析字节的约束。Python BufferedReader 可能预读，不能据此新增“内核物理读取绝不超过该字节数”的保证。大小低报文件的 fallback 可能同时持有多个 buffer，因此也不能把小文件收益推广成所有异常输入的峰值都会降低。

### 关闭实际发现的描述符泄漏

旧终态读取函数在 `os.open` 成功后，把 descriptor 直接交给 `os.fdopen`。若此时目标为目录，`fdopen` 可在接管 descriptor 前失败，留下一个 descriptor。

现在以外层 `try/finally` 唯一持有 descriptor，内部使用 `fdopen(closefd=False)`，将关闭责任放在同一个出口。实际测试中两个相关故障路径从基线遗留 1 个 descriptor 变为候选遗留 0 个；被测成功和失败路径均满足关闭断言。

本次六机被测的 operator/Python 路线在普通 status/read 中每次运行一个远端 Python helper；helper 退出后操作系统也会回收描述符，因此上述结果不等于跨所有 RPC 永久累积泄漏。isolated jobctl 是另一条执行路线。本轮直接证明的是函数级故障路径与关闭行为。

## X230 组件实测

使用实际 Rust 源文件抽取的原始 Python 函数体，不重写被测实现。六个合成文件场景，每个场景 4 个 ABBA blocks，共 96 个独立 Python worker；每 worker 256 次计时调用、16 次 warmup，以及另外 3 次未计时 tracemalloc 样本。共 24,576 次计时调用，96 个 worker 全部成功，四个 block 的 CPU 方向在六个场景中均一致。

| 场景 | A CPU μs/调用 | B CPU μs/调用 | 配对 block CPU 中位变化 | A traced peak 中位（字节） | B traced peak 中位（字节） |
|---|---:|---:|---:|---:|---:|
| 私有小 JSON | 82.986 | 44.871 | −45.33% | 4,200,374 | 7,225 |
| 私有 64 KiB JSON | 259.479 | 191.601 | −25.38% | 4,200,434 | 136,400 |
| 终态小文件 | 66.049 | 34.444 | −52.46% | 1,054,678 | 7,506 |
| 终态 64 KiB 文件 | 106.277 | 48.713 | −51.91% | 1,054,738 | 73,071 |
| completed status 组件 | 236.625 | 161.319 | −32.86% | 4,200,374 | 9,543 |
| live detached 组件 | 384.160 | 303.323 | −23.17% | 4,201,501 | 13,918 |

A/B CPU 列是各自 worker 单次 CPU 的中位数；百分比列是四个 paired-block ratio 的中位数，两者不是同一种聚合，不能直接用前两列相除复算百分比。计时包括结果相等断言，排除 worker 启动和 untimed allocation 阶段。

分配列为每个 arm 的 8 个 worker ×3 次未计时样本，共 24 个 traced peak 的中位数，不是所有样本中的最大值。

两个 64 KiB 夹具都是小 JSON 加尾随空格，用于隔离读取分配机制，不代表复杂 64 KiB JSON 对象的通用解析成本。live-detached 场景在 Linux 上从 `/proc` 取得身份，不代表 Mac 上 `ps` 子进程的开销。

tracemalloc 是 Python 跟踪到的分配，不是 RSS。全部 96 个 worker 在计时前、计时后及分配采样后的生命周期 HWM 都为 23,588,864 字节，未观察到 HWM 下降。它可能已由解释器、源码 AST、夹具或此前生命周期峰值决定，不能当成稳定生产内存。

独立程序从原始 cells 与时钟端点重新计算全部统计，核对来源绑定，并独立重建五个固定场景的夹具和期望结果 digest。live 场景可核对持有进程 PID、绑定 digest 及 worker 的相等断言，但原始 boot/start 身份字节未保留，无法独立重建当时的完整期望身份。29 项检查通过；重建汇总与原文件逐字节一致，SHA256 为 `e144a0e80d6a68dbe73e835e7b007a149adf533f98b3ca31ebb5da85b64002d4`。worker 逐次执行相等断言，但没有保存每次函数返回全文，不能称独立重哈希了 24,576 份原始返回全文。

## 完整资格与差分验证

X230 最终语义验证：14 个测试方法、238 条观测，组成 119 对 A/B，0 失败、0 错误、0 跳过；返回值或异常身份保持一致，descriptor 关闭差异按预期改善。覆盖上限、非法 JSON/编码、大小低报、高报、短读、EAGAIN、EIO、增长、截断、替换、权限及 metadata 变化、终态 witness，以及完整 bound helper。

第二次完整资格在全新的 `target-fresh-02` 中完成。format、fmt-check、工具自测、all-targets/all-features strict Clippy（`-D warnings`）、测试构建、逐项隔离测试、测试日志独立审计及 release 八个阶段均退出 0。根 crate 的非测试 library 和五个测试产物全部为 `fresh=false`。

**1,637 passed /0 failed /33 ignored，1,670 selected，5 个 test binaries，0 test retries。** 33 个 ignored 条目没有在该资格流程中执行。实际 `source-map.json` 有 219 个输入，原始字节与从 R18 Git 证明推导的候选输入清单一致，SHA256 为 `aa48d4ada7b35363188424c3e60d5dd209af5cdd3cb5e917ff0f4aaecbdbc5df`。完整资格输入目录的 281 个文件前后冻结，仅 `jobs.rs` 相对于 R18 改变。

完整归档回传后，另以实际 qualification report、测试前后输入 map、freeze、resolution 和 R18 Git 证明完成 22 项源码绑定检查。219 项输入全等，候选 `src` 树重新计算为 `3aa8c9aadbf42b6a0ebdac3954bd1e64b4055e20`，与实际创建的 Git tree 一致。收据 `local-development/review/qualified-source-binding-01.json` 的 SHA256 为 `1b8fbf0126d2f78e1c588df7812aeb8a332398cfcfb2294cea9764e72d6f18f3`；三个实际 ELF 的路径、大小和哈希同时与验收及 resolution 对齐。尚未产生的发布 commit 状态在该收据中另列，不假称已经验证最终提交。

完整资格耗时 1,924.175 秒，随后独立验收耗时 12.361 秒。独立验收 24/24 检查通过；最终 resolution 的 12/12 检查通过，并绑定第一次拒绝、复用的语义/组件证据、微型 ABA 诊断、新工具 manifest、两阶段原始日志以及 qualifier PID/start-ticks/wait/reap 收据。已确认 qualifier PID 2816940 被 wait/reap 且对应 `/proc` 路径消失。

| 最终 R19 产物／收据 | SHA256 |
|---|---|
| `hepta-runtime`，14,369,848 字节 | `adab5f27f89b3cac6adaec916110a48d80697db9667e3bd7ee0fc713fe770a09` |
| `hepta-runtime-jobctl`，739,016 字节 | `61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62` |
| `native_process_driver`，2,896,456 字节 | `51165c1e38409248f5fdb7da2036ebe5e05eec7576035e95bd4b8e2a5c675530` |
| `qualification-02/report.json` | `44a352c14bb83d093058ccbbc2c99fab913ef9af0b3400b00750dc46ad69cc16` |
| `independent-acceptance-02.json` | `374d6bf3e7201522f8145b105a10c372eaedc5bba9099ca92857367637b65ea9` |
| `qualification-resolution-02.json` | `656bca705be3ac3902760d1998e7b999769a3f6884e39ae08150938c5c6b8867` |

jobctl 与 R18 的相等结论包含实际逐块字节比较；runtime 和 driver 按本次实际产物身份分别绑定，不推定它们与旧版本相同。

### 保留的第一次资格拒绝与构建环境修正

R19 `qualification-01` 的八个资格阶段都返回 0，1,637 passed /0 failed /33 ignored，所有根 crate 产物均重新编译；但独立验收拒绝了该次产物。jobctl 源码未变，重新构建的二进制却从基线 SHA256 `61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62` 变成 `43a40254d5812a81d9824e30ad75c0eca6cf9ddab04e03a1afb48de102797510`，因此该次产物没有进入六机性能测试。

原因调查发现，第一版启动器显式设置了空的 `CARGO_BUILD_RUSTC_WRAPPER` 和 `CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER`，而 R18 的这两项完全不存在。Cargo 1.95 的空 workspace-wrapper 路径不会执行外部包装程序，却仍参与 workspace 编译单元的 metadata 标识计算。实际 fingerprint 中 21 个外部依赖一致，workspace library 的标识不同。二进制 section 和字符串检查只能定位差异，不能单独证明语义相等。

在同一台 X230、同一 Rust/Cargo 版本上另做一个仅依赖 std 的微型 workspace，同时切换两个 `CARGO_BUILD_RUSTC_*WRAPPER` 设置，在三个事先不存在的 target 中执行 unset / empty / unset。两个 unset 结果的 metadata、最终二进制及 TypeId 输出完全相同；empty 的 metadata、二进制及 TypeId 改变，数值结果仍为 42。8 项检查通过，测试源码和现有 runtime 产物前后未变。该实验没有逐个隔离两个环境键；workspace-wrapper 空路径参与 metadata 哈希的具体机制由对应版本的 Cargo 源码链定位。这是构建环境的因果诊断，不算入 runtime 性能样本。第二次资格的实际 jobctl 通过严格 R18 身份门槛并恢复为逐字节相同的产物，闭合了这一构建差异的验证。

第二版启动器彻底移除四种 wrapper 环境键，以相同冻结源码和另一个事先不存在的空 target 重新运行完整资格，并继续要求 jobctl 与 R18 逐字节一致。原 `qualification-01`、失败的独立验收、原启动器和所有原日志均保留；没有放宽门槛，也没有用复制基线二进制代替重新构建。此前成功的 X230 语义测试和组件 ABBA 通过源码及原始文件哈希复用，没有再次运行以挑选结果。

## 六机整链吞吐与资源

预先固定 ABBA，C1/C8/C16，每 cell 192 measured +24 warmup，操作按六个 host 与 status/read 平衡。每个 arm/C 的 rate 为成功调用总数除以各 cell 耗时之和；CPU/call 为同一 controller PID/start-ticks 的同步 CPU ticks 差除以调用数；p95/p99 由该 arm 的原始延迟合并后取 nearest-rank。

实际执行了 2,304 次计时调用、288 次 warmup、72 次初始化后／重启检查，共 2,664 次工具调用，失败数为 0。每个 arm/C 有两轮、384 次计时调用。六个 campaign 阶段均退出 0，逐阶段前后输入检查全部通过；测量前静置实际为 90.015 秒。

| 并发 | A 调用/秒 | B 调用/秒 | 吞吐变化 | A controller CPU ms/调用 | B controller CPU ms/调用 | CPU 变化 |
|---|---:|---:|---:|---:|---:|---:|
| C1 | 4.4287 | 4.3849 | −0.9884% | 129.9740 | 129.2708 | −0.5410% |
| C8 | 23.3520 | 23.4021 | +0.2143% | 72.8385 | 72.8646 | +0.0358% |
| C16 | 23.2211 | 23.3239 | +0.4427% | 73.4115 | 73.1771 | −0.3193% |

| 并发 | A p95 ms | B p95 ms | p95 变化 | A p99 ms | B p99 ms | p99 变化 |
|---|---:|---:|---:|---:|---:|---:|
| C1 | 282.833 | 285.908 | +1.0874% | 304.695 | 309.264 | +1.4995% |
| C8 | 424.286 | 427.338 | +0.7194% | 450.847 | 459.459 | +1.9101% |
| C16 | 809.357 | 797.698 | −1.4406% | 847.542 | 882.187 | +4.0876% |

主工作点 C8 的平均调用速率几乎不变，controller CPU 没有下降；C16 的吞吐变化也很小，p95 改善的同时 p99 上升。p99 没有作为预注册采用门槛，仍完整列出。B 的 C8 两轮速率分别为 23.7671 和 23.0481 调用/秒，跨度约 3.12%，大于其相对 A 的 +0.2143% 汇总差异；这组有限样本没有建立可重复的整链吞吐提升。在当前负载下，C16 也未比 C8 获得更高的调用速率。

主 controller 的 `shutdown` 相位 HWM，A 两轮为 `[17880, 17344]` KiB，B 为 `[17804, 17628]` KiB；简单均值为 17,612 → 17,716 KiB，即 **+104 KiB（+0.5905%）**。这是各进程生命周期高水位的比较，不是每次调用的分配，也不是稳态 RSS。原报告保留另外四个重启相位及所有资源缺测记录；它们没有混入上述主 controller 均值。该结果与组件 worker 的平坦 HWM 一样，不支持常驻内存下降的结论。

同一首运行阶段的 tree RSS 峰值简单均值为 115,178 → 116,096 KiB（+918 KiB）。该值来自异步进程采样，存在共享页重复计数及短命后代缺测，只能按这一观测口径比较，不能视为精确的独占内存。完整 paired 指标及原资源缺测保留在 `local-development/review/derived-campaign-metrics-01.json`。

本节及下文的数字最初来自关闭测量窗口后生成的 `closed-campaign-summary-01.json`，SHA256 为 `0a7466899e459a7e3d75a43f0c279f53c85bde6ffa96e91ba79b1ae53786d76b`。随后已完整传回原始归档，独立验证全部 83 个运输文件与九个证据包，并从原始材料重新运行三个冻结分析器。重算结果及其文件 SHA256 均与 X230 原分析相同，详见下文；这些步骤没有重跑性能负载。

完整 transport bytes、frame index、monotonic endpoints、controller ticks、resource trace、正常退出与原作业不变检查均保留，并已由 X230 上的独立分析器复算。该指标是已完成作业的 observation 调用吞吐，不是任务启动吞吐或集群计算吞吐。controller CPU 不包含 SSH、远端 Python 或整个集群；异步子代采样有缺失及共享页重复计算的限制。

采用筛选在首次测量前已冻结：组件 private-small 与 terminal-small 的跟踪峰值各降低至少 90%；C1/C8/C16 每档 B rate 至少为 A 的 95%，p95 至多为 A 的 110%；全部正确性与恢复 gate 通过。这个有限样本筛选不是统计显著性或非劣性置信区间。没有删除慢调用，没有自动重试或反复跑到通过。

## C32 突发与六机恢复

C32 使用实际 R19 二进制 `adab5f27…`、workers=2、arena=1，完成两次各 32 个客户端请求的突发。每次均在首个回复到达前启动了全部请求，客户端 pending 峰值为 32；原始分类结果如下。

| 突发 | 成功 | capacity rejection | 其他错误 | 成功调用/秒 | 成功 p95 ms | 拒绝 p95 ms |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 16 | 16 | 0 | 21.9888 | 714.064 | 39.734 |
| 2 | 16 | 16 | 0 | 19.0455 | 827.551 | 49.698 |

成功速率只使用成功调用数，拒绝不计入吞吐。两次分别耗时 0.7276 和 0.8401 秒；每类每轮仅有 16 个样本，表中 p95 在该样本量下也是该类样本最大值。32 个客户端 pending 请求不能证明 32 个内部 native pool identities 同时存在，内部 admission 峰值未遥测；本次 16/16 分类是实测结果，不是验收时强制的数量。

排空后的 96 次新 C1/C8 检查及重启恢复通过；它们是计划内的新请求，没有自动重试。连同 64 次突发、24 次 warmup、18 次初始化后／重启检查，边界阶段合计 202 次工具调用、204 个经独立验证的 RPC frames，其他错误为 0。原独立分析的 `evidence_verified`、`diagnostic_passed` 与 `drain_and_recovery_passed` 均为 true。

六机恢复使用相同 R19 二进制，完成 6 次真实启动、12 次 same-key lookup 和 12 次取消；六台主机的 execution count 都为 1，重启后终态字节均保持不变。原独立验证检查了三个 controller 代际，共 90 次 native 调用、36 次独立 SSH 检查、93 个 RPC frames 和 72 份 SSH stdout/stderr，自动 RPC 重试为 0。

ROG 路线的自有私有 SSH master 中断实际执行并通过：信号收据绑定原 PID/start-ticks，记录 pidfd 确认原进程结束，并验证后续使用替代 master。相关资源 trace 的退出竞态、权限及字段缺测原样保留，没有将不完整子代采样当作整个集群资源统计。恢复独立验收的 `verified` 为 true。

这些结果覆盖自有控制器和私有 SSH transport 的中断、重启及幂等恢复，不等于主机掉电、WAN partition、owner transfer 或任意外部副作用的 exactly-once 保证。Mac 的 account/PID-start 取消边界仍为 best effort。

## 完整原始证据的独立复算

本地将 172 个分片重新组装为原始外层归档，核对完整大小、SHA256 与 Git blob 身份，再恢复全部 83 个运输文件。九个内部归档分别通过原打包器的完整 manifest 验证，之后才解包和运行原分析器。独立复算收据为 `local-development/review/offline-raw-audit-01/report.json`，SHA256 为 `a700ef8f737bf2ceb9704930a9afc6fc9c6c57f8cc0f5953a12f9163a78ddf38`。

| 分析 | 原文件与重算文件共同 SHA256 | 实际核对结果 |
|---|---|---|
| native observation | `3b2bea3c5352dfbdc798b2ac7da44ad60e3cb06704728aeecfada429b6863355` | 2,672 个完整帧，2,664 次工具调用；结果逐字段及文件字节身份一致 |
| C32 boundary | `0685551e81adfce9bbb0fc7b2e0a71d3390d25b8a40b61cae10dd0eaab589de1` | 204 个完整帧，202 次工具调用；成功、明确拒绝和其它错误分类一致 |
| cancel recovery | `9945639e0ca109de0b00ec88fae4282a048163cf67a648b5197ec36f75a81364` | 93 个完整帧，90 次 native 调用，36 次独立 SSH 检查及 72 份 SSH 流一致 |

三个当前 campaign 共 **2,956 次工具调用：2,924 成功、32 次预期容量拒绝、0 其它错误；2,969 个完整 RPC 响应帧**。36 次独立 SSH 检查另列。组件计时调用、资格测试、机制诊断与发布工具调用也不加入该计数；独立 campaign 的性能速率不合并。

证据导出阶段的文本 MCP 读取出现超时，原错误及已知状态保留；第一次被终止的传输编排未持久化全部内存日志，这一缺口在 orchestration 记录中明确说明。已通过哈希的分片被复用。之后沿用原受限 holder，以新的只读 reader 将同一归档复制到 Mac；原归档、副本和最终组装结果的完整 SHA256 相同，holder 的前台 SSH 退出 0，自己的临时 agent 已回收。剩余分片经专用二进制接口完成，版本、偏移、长度和块哈希逐项验证。上述传输超时发生在已关闭的测量窗口之后，不隐藏为成功，也不计为性能实验重试。

## 失败尝试与审计边界

早期语义测试发现基线本身有 descriptor 泄漏；第一份 oracle 错误地要求基线也不泄漏，因此该失败保留。随后修正 oracle、增加真实修复。独立审查又发现续读 `None` 时直接拼接会抛出 TypeError，最终 revision3 修复并补充回归。

早期云端组件 ABBA 在首个 live-detached A cell 因 supervisor identity 不适配该环境而失败，该场景尚未运行 B；它完整保留，不算入 X230 性能结果。修正后只做六场景 × A/B 的小型 fixture smoke，正式机制 ABBA 仅在 X230 执行一次。

独立组件离线审计的第一次尝试误把“9 个证据文件”理解为归档只有 9 个成员；实际还有 1 个 manifest。该审计失败与修正后的 29 项通过记录都保留，未重跑性能。

第一次预资格外层 launcher 在超时路径有收尾元数据和子代进程组处理限制，且工具 manifest 只在开始检查一次。第二版新增自有子进程组清理、逐阶段证据稳定性检查及 qualifier PID/start-ticks/wait/reap 收据；三个本地子进程成功、非零退出和超时自测通过。最终接受仍依靠正常退出、完整 qualification 独立审计和测量前进程检查；这些自测不代表所有操作系统或孙代故障情形都已验证。

Cargo 源码链的独立离线 addendum 第一次使用了错误的 AST 路径选择器，未选中嵌入的 `src/lib.rs` 文本；失败和修正后的 21 项检查均保留。该修正没有重新构建微型工程或运行任何性能负载。

## 当前停止点

按预注册标准，本轮采用 R19 的源码改动：两个小文件场景的 Python 跟踪分配降幅超过 90%，函数级 descriptor 故障路径修复通过，完整资格、C1/C8/C16 的吞吐/p95 筛选、C32 排空及六机恢复全部通过。`adoption_screen_passed=true` 表示这组固定门槛已满足，不表示集群吞吐或 RSS 已改善；实际 C8/C16 的细小速率变化不足以建立这种结论。采用范围是已经验证的局部资源优化与正确性修复，没有改变已冻结的 workers、并发预算或安全检查，也不将本轮选择表述为生产服务已部署。

此前 R16 路径预解析／buffer 复用、R17 lazy 请求分配、workers1/4 及更大哈希 buffer 的具体取舍见 [R16–R18 报告](X230_OPTIMIZATION_20261104_R16_R18.md)，没有把已否决方案重新包装成新收益。

完整内容校验已使用 ring SHA256；X230 没有 SHA-NI／AVX2。不能把换成 ring 当作尚未做过的新优化。减少 phase-boundary 的完整 pin 校验、缓存成功校验或改变持久化顺序会改变现有契约；本轮没有用这些变化换取表面吞吐。

更深的等待机制、持久 helper、owner 协议或新的硬件加速路径都需要独立设计和测量。这一轮的结论限于实际测试过的代码、配置、硬件和负载，不宣称已经证明全局最优或所有可能优化都不存在。

## 产物与复核

九个远端证据包已经由 X230 采集器实际产出。下表的归档名称、精确字节数和 SHA256 直接取自原始 `publication/collection-control-01/03-package.stdout`（SHA256 `bc80049a69563e993ca42f71bc0e7d461af3f59940026cfc4840fdfeb1bf9df2`）。每个包还保留同名 stem 的 `.manifest.json` 与 `.archive.json`，用于独立核对文件清单、原始字节和归档身份；包内材料的资格 verdict 保留原样，其中 `qualification-01` 仍是被拒绝的第一次产物。

| 归档 | 字节数 | 归档 SHA256 |
|---|---:|---|
| [qualification-01.tar.gz](../tools/x230/20261104/r19/qualification-01.tar.gz) | 1,593,948 | `17a74596608e993ce14a98ea013b4c7eedf6e2da33c3f6327891553a1814f766` |
| [prequalification-component-01.tar.gz](../tools/x230/20261104/r19/prequalification-component-01.tar.gz) | 108,618 | `185637589688bb84864d265d3a3f5fb69b309dcda244a0015765a5291139c471` |
| [qualification-02.tar.gz](../tools/x230/20261104/r19/qualification-02.tar.gz) | 1,594,996 | `b566ce6cadf11a34ac28ce91a418a143dc9cacb6e50afde72f66d1e4a9bea599` |
| [qualification-resolution-02.tar.gz](../tools/x230/20261104/r19/qualification-resolution-02.tar.gz) | 48,052 | `90cb0793f5313fce062a379f3a168602ee89dc9cd09501a56ca5594ab7c3ab83` |
| [qualification-diagnostics-01.tar.gz](../tools/x230/20261104/r19/qualification-diagnostics-01.tar.gz) | 249,406 | `6b4a9cc11b4cc957b55ca056e0fb8aa8972106f332bc043c378c5b6b9263ba21` |
| [campaign-control-01.tar.gz](../tools/x230/20261104/r19/campaign-control-01.tar.gz) | 268,975 | `727437213953a8b9f0361f33ecd6a656a30b8282072daefb890849cf1ef121d3` |
| [native-observation-01.tar.gz](../tools/x230/20261104/r19/native-observation-01.tar.gz) | 2,180,696 | `048a3ab43569a727336e5af4ca329bd9632c87bcce8b6b02d685150d1df92110` |
| [native-boundary-01.tar.gz](../tools/x230/20261104/r19/native-boundary-01.tar.gz) | 261,894 | `8d948277ae47edfa3a089d09b49e8afdb11bd699b3c98bc9ffee6e607cacaec5` |
| [cancel-recovery-01.tar.gz](../tools/x230/20261104/r19/cancel-recovery-01.tar.gz) | 263,130 | `ca9b3041ca4ba40f30a85607a47d151c132e2a1918d494b1d925636dda0b531d` |
| [local-development.tar.gz](../tools/x230/20261104/r19/local-development.tar.gz) | 936,654 | `551477872059dd7700e4c43722a5f116ccf9c106d94f5bafe1a811ad735ee5bc` |

前九包来自已关闭测量与构建证据写入的 X230 目录；第十个 local-development 包在完整原始数据回放、219 输入源码绑定及收尾观察记录完成后生成，保留代码与补丁修订、失败尝试、独立复核、两次 Mac holder 的文本收据及组件离线重算材料。十个证据包及全部 manifest/receipt 已生成。九个远端包共恢复 7,042 个唯一文件，55 个重复成员逐字节相同，100 个显式计划哈希绑定全部匹配。归档内的发布前报告快照保留当时状态；当前 docs 报告另补最终归档身份，避免归档哈希自引用。

原组件传输归档另以 [`component-evidence-01.tar.gz`](../tools/x230/20261104/r19/component-evidence-01.tar.gz) 单独保留，精确为 29,364 字节，SHA256 为 `4d9787b50d914d3407ce5f15465060ff5e35828b5f489528fb39cc4dbc6a8dd5`。它与先前收到的组件 tar 逐字节相同，供组件离线审计检查原始传输身份；它不计为第十一个实验包。

外层 `r19-transfer-envelope-01.tar.gz` 仅用于传输九个远端包及其 manifest、收据和已关闭的附加文件。原封装收据记录 83 个被索引的数据文件，外层归档为 7,712,102 字节，SHA256 `6e329b2b9adffc23c06496c68efeeea07605ce1ee28079a92cc3e2d508accd93`。这个数是运输层被索引文件数，不是九个内层归档的总成员数；外层不改变内层内容，也不计作额外实验包。该身份与实际本地组装结果一致；恢复收据 SHA256 为 `5b7797f667abb026e7fc2aac5c126165dbc282382c1e5f14d3f5158d3559a310`。完整接收、九包验证及三个原始分析的确定性复算均已完成。

各包职责、原工具身份、native／C32／恢复的离线重算命令，以及组件 helper 的恢复布局见 [R19 证据说明](../tools/x230/20261104/r19/README.md)。资格包保留构建与测试证据以及产物哈希，未收录整个 target 树或 ELF 可执行文件；仅靠这些归档不能在另一台机器上重新核验原 ELF 的实际字节。


### 发布与实际二进制位置

本轮沿用 [draft PR #87](https://github.com/TrillionniumFoundation/hepta-runtime/pull/87) 及其原 base。编译源码的父提交为 `a83fe08d736522cf01adee53902e3c13fbc1d5ae`，实际候选 `src` tree 为 `3aa8c9aadbf42b6a0ebdac3954bd1e64b4055e20`；219 个编译输入与完整资格证据相符。最终提交同时包含该源码树、本报告和证据，文档及归档文件不计入 219 项编译输入。

最终本地闭包计划 SHA256 为 `670c03c9e809d78ab0419507943afbf50bdb6489c2930934a05223196833b357`，闭包收据为 `deaaef8402f6f504580e9b6b3c3a71729617e347bfabfcedb29b79b7033ecb99`，本地归档批次报告为 `be0f664d5c2d9db2d09f0ba4e2d0c460ef69c6139415805ea0d9c779f8781786`。逐文件字节数、SHA256 和 Git blob 身份见 [最终文件清单](../tools/x230/20261104/r19/publication-manifest.json)。该清单不对自身做循环哈希。

X230 上已实际构建并通过资格的 ELF 保存在：

- `/home/qian/hepta-runtime-optimization-20261104-r19/qualification-02/hepta-runtime`
- `/home/qian/hepta-runtime-optimization-20261104-r19/qualification-02/hepta-runtime-jobctl`
- `/home/qian/hepta-runtime-optimization-20261104-r19/qualification-02/native_process_driver`

这些绝对路径、文件大小和完整哈希已在实际 qualification、acceptance、resolution 与最终源码绑定中对齐。原失败资格、两个 target 树、六机原始证据及历史源码均保留。此交付是已构建和验证的候选与草稿 PR，常驻 Mac controller 和全局服务配置维持原状态。

