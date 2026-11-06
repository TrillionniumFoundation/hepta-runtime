# X230 R36：拒绝采纳，保留 R24

**R36 REJECTED。完整资格验证和源码提交的 CI 均通过，但必选 normal lifecycle 性能门限失败，继续保留已接受的 R24。** 六机 observation 通过原非退化筛选，没有建立稳定加速证据；正常 C6 lifecycle 的总体吞吐下降 **5.3884%**，launch 吞吐下降 **11.2386%**、p95 增加 **23.1775%**，launch Controller CPU 也超过原容差上限。本轮停止后续实验，**异步 read 补充与 saturation 均未执行**，不重测以寻找通过结果。[Observation 原报告](../tools/x230/20261106/r36/performance/observation-summary.json) · [Lifecycle 原门限报告](../tools/x230/20261106/r36/performance/lifecycle-gates.json) · [外层拒绝终态](../tools/x230/20261106/r36/performance/lifecycle-parent.json)

候选源码保留在 `perf/x230-r36-20261106`，提交 `d3590733f6c301a91cb8f4fcc54ee5c3251a9530`，对应草稿 [PR #106](https://github.com/TrillionniumFoundation/hepta-runtime/pull/106)。发布候选与失败证据不表示采纳或部署；已接受性能基线仍为 R24 `baab4def80be7af015b2e7a594cb302f66c4130e`。

## 候选范围与实际构建身份

普通请求与保留身份请求在成功 admission 后，原先会把已完成的 `Vec<Record>` 再深拷贝一次，再发布到热缓存。R36 只将 `request_audit.rs` 中两个末端调用改为现有 `cache_hot_owned`，移交该向量；初始 `hot_snapshot` 克隆保留，拒绝后的缓存仍可复用。两项相邻测试扩展了拒绝后的缓存完整性、owner 隔离，以及归档身份被拒后新身份仍可继续的检查。生产代码仅两个调用点改变，另有两个测试文件修改。[源码审查](../tools/x230/20261106/r36/reviews/source-review.md)

正常 observation／lifecycle 主要沿用原本已移交缓存所有权的 batch 路径；R36 改动的是普通／保留请求的两个末端路径。本轮没有对这两个路径做命中次数遥测，因此原始性能差异不能证明这次复制减少造成了回归或收益。面向相关路径覆盖的异步补充协议已经封存，但因必选门限失败而未执行。源码配对和按冻结门限拒绝采纳的决定不依赖这种因果归因。

持久化写入与 fsync 顺序、durable identity、lookup pin、owner 边界、unknown 结果和取消语义保持原顺序。提前取走整份缓存的方案在冻结前被否决：纯拒绝也会清空缓存，使下一次 admission 在锁内重读热记录。该方案没有进入候选。[静态优化边界](../tools/x230/20261106/r36/evidence/static-frontier-review.md)

本轮 Git 父提交为 `86155fbf3b89e5a77e2a4aadebd2128c663fe50b`。已逐一读取已发布候选提交中的全部 **220 个编译输入**，与 X230 实际 `source_tested` 比较，全部一致；`source_tested == source_after`，相对 R24 的差异限于三个声明文件，原 **19 个资格工具**前后完全相等。[Git 与测试源码核对](../tools/x230/20261106/r36/candidate/published-source-review.json)

预格式化输入没有冒充实际构建输入。rustfmt 仅将 `request_audit_lookup_tests.rs` 中一个表达式换行，生产文件不变。准备补丁与实际补丁分别保留，格式化后的 diff 另行复核。[准备补丁](../tools/x230/20261106/r36/candidate/prepared.patch) · [实际合格补丁](../tools/x230/20261106/r36/candidate/qualified.patch) · [实际源码 map](../tools/x230/20261106/r36/candidate/qualified-source-map.json) · [格式化审查](../tools/x230/20261106/r36/reviews/postformat-source-review.json)

| 身份 | SHA-256 |
| --- | --- |
| 准备补丁 | `c693664d88e1bbed7e1257ad292d9d7b54eb3521db039cc1b8468f1e7b13caf1` |
| 实际合格补丁 | `25c5bf3054efaa60be74fbb3ed1628c4833a0ae2564079744d2fc56a95ea588b` |
| 实际源码 map | `6c6d3512c0c41268e975ad40d0c1d6642cddec7757c4f0bbe4e1a97580e3988b` |
| 合格 `hepta-runtime` | `c43db0ef333ce7862080157a1a7fa892ae401a065bdfa96d97d4fd29f2a4eccb` |

## 资格与 CI：通过，但不替代性能门限

完整资格验证于 **2026-11-06 09:33:54–10:08:58 UTC** 在独立 R36 source／target 上执行，`jobs=2`，无自动重试，未修改生产服务。原始终态为 `succeeded`、退出 0，输出完整且持久化；准备报告确认拥有的子进程已关闭、进程组不存在。[资格报告](../tools/x230/20261106/r36/qualification/report.json) · [原始终态](../tools/x230/20261106/r36/qualification/terminal-status.json) · [准备终态](../tools/x230/20261106/r36/qualification/preparation.json)

| 验证 | 原始结果 |
| --- | --- |
| format、fmt-check、harness-tests | 三阶段退出 0 |
| Clippy | `--all-targets --all-features -- -D warnings` 退出 0 |
| test-build | 全 target／feature 测试构建退出 0 |
| isolated-tests | **1,645 passed，0 failed，34 ignored，0 retries** |
| audit-isolated-tests | 独立库存与原始日志审计退出 0 |
| release | release bins／examples 构建退出 0 |

测试数量来自[原始 isolated summary](../tools/x230/20261106/r36/qualification/isolated-tests-summary.json)；34 个 ignored 没有算作已执行通过。资格报告 SHA-256 为 `13faedb85f2a4d356575733deda6b51009dfe0f14399da7424032523dba2f492`。

X230 外部 Rust CI 于 **10:20:31 UTC** 完成，六阶段通过，包括 `cargo check --locked --all-targets --all-features`、结构化 nextest 库存和单线程、零重试 nextest。原始输出审计确认 **1,645 PASS、0 failed、34 ignored、0 retries**；源码未变，六个阶段拥有的进程及进程组已消失，子进程已回收。[外部 Rust CI 原报告](../tools/x230/20261106/r36/rust-ci/report.json)

GitHub 源码 PR 的独立运行 **42200291494** 中，exact-head job **127833605232** 与 prospective-merge job **127833605008** 均为 `completed / success`，包含各自 checkout 身份验证步骤。这是源码提交 `d359073…` 所对应的 CI；不能据此外推后续证据提交的 CI。外部原报告中的 `hosted_actions_passed=false` 保留不改，托管 CI 结论由这份另行取得的回执支持。[源码 PR CI 原回执](../tools/x230/20261106/r36/rust-ci/source-pr-ci-jobs-complete.json) · [GitHub 运行](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42200291494)

## 六机 observation：非退化通过，没有稳定加速

A 为 R24，B 为 R36，ABBA 四轮，C1／C8／C16；每臂每档 **384 次 measured calls**。原门限分别为吞吐 B/A ≥ 0.95、p95 B/A ≤ 1.10、Controller CPU/call B/A ≤ 1.10，三个并发档分别判断；RSS 同时满足绝对与比例限制。原 observation 的正确性、证据和性能筛选均通过。[原 summary](../tools/x230/20261106/r36/performance/observation-summary.json) · [原 native analysis](../tools/x230/20261106/r36/performance/observation-native-analysis.json)

| 并发 | 调用/秒 A → B | 吞吐变化 | p95，ms A → B | p95 变化 | Controller CPU，ms/调用 A → B | CPU 变化 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| C1 | 7.782382 → 7.713705 | −0.8825% | 183.345942 → 184.822963 | +0.8056% | 31.536458 → 31.406250 | −0.4129% |
| C8 | 54.586700 → 53.380095 | −2.2104% | 194.334245 → 206.545763 | +6.2838% | 19.479167 → 19.296875 | −0.9358% |
| C16 | 54.455510 → 54.693567 | +0.4372% | 363.604565 → 358.605707 | −1.3748% | 20.364583 → 20.052083 | −1.5345% |

Controller 采样 RSS 峰值为 **19,032 → 18,864 KiB，下降 168 KiB**，原上限为 `min(19,032+512, 19,032×1.05)=19,544 KiB`。这是有限频率采样峰值，不是集群内存或分配上限；原采样缺失和进程退出记录保留。C8 两个相邻配对的吞吐变化为 −4.867%／+0.536%，C16 为 −1.453%／+2.351%；RSS 第一对增加 96 KiB、第二对下降 168 KiB，方向并不一致。C1 p99 从 206.755035 增至 233.373984 ms（+12.8746%），虽不在原门限中，也没有删除。[独立 observation 复核](../tools/x230/20261106/r36/reviews/observation-review.md)

原容量边界合计 32 次成功、32 次精确 capacity rejection，其他错误为 0，排空及恢复检查通过；原正确性 canary 完成 6 次新启动、12 次 lookup、12 次取消。该 canary 不能替代以下必选正常 lifecycle ABBA。Observation 的速率描述已完成作业的 status/read RPC，不能称为任务计算吞吐或最大内部并发容量。[原 observation 父报告](../tools/x230/20261106/r36/performance/observation-parent.json)

## 正常 C6 lifecycle：四项必选失败，拒绝采纳

四轮 ABBA 共 24 个新作业；每臂总体 60 次 operation 调用，launch 与 live concurrent-cancel 各 12 次。四轮 canary、四轮 audit 和 summary 均退出 0；必选 `normal-lifecycle-gates` 退出 1，内层及外层报告均为 `passed=false`，外层 `adoption_passed=false`。输入未变，编译监测有效，没有自动重试；这是原性能门限的拒绝结果。[原 gates](../tools/x230/20261106/r36/performance/lifecycle-gates.json) · [原 summary](../tools/x230/20261106/r36/performance/lifecycle-summary.json) · [内层报告](../tools/x230/20261106/r36/performance/lifecycle-report.json) · [外层报告](../tools/x230/20261106/r36/performance/lifecycle-parent.json)

| 必选分组／指标 | A | B | 原门限与判定 |
| --- | ---: | ---: | --- |
| all_operations 吞吐，RPC/s | 8.101553311 | 7.665012769 | B/A **0.946116438946 < 0.95**，失败（−5.3884%） |
| launch 吞吐，RPC/s | 7.300411690 | 6.479951211 | B/A **0.887614491524 < 0.95**，失败（−11.2386%） |
| launch p95，ms | 827.582680 | 1019.395308 | B/A **1.231774579913 > 1.10**，失败（+23.1775%） |
| launch Controller CPU，s | 0.09 | 0.12 | B **> 0.11 s** 原上限，失败 |

Lifecycle CPU 门限是 A 的 CPU 总量加声明的 tick 容差，并非 observation 的 10% 相对门限。Launch 的 100 Hz 计数对应 A 两轮共 9 ticks、B 共 12 ticks；原容差允许额外 2 ticks，上限 11 ticks，仍超 1 tick，不能归为浮点误判。全部 Controller CPU 不包含远端主机；被回收本地子进程 CPU 在原件中另列。[独立 lifecycle 复核](../tools/x230/20261106/r36/reviews/lifecycle-review.md)

`all_operations` 的 p95 和 CPU 通过。`concurrent_cancel` 吞吐 B/A 为 **0.997479131547**、p95 B/A 为 **0.953542932804**，CPU 为 0.06 → 0.07 s、上限 0.08 s，三项均通过。Controller RSS 为 **17,436 → 17,696 KiB（+260 KiB）**，低于 17,948 KiB 上限。这些通过项不抵消四项必选失败；same-key 等描述性分组的全部原值也保留在 gates 中。

独立复核从保留的 20 个 C6 cells、120 条 latency 重算速率、分位数、CPU 容差和 RSS 门限，并核对失败状态传递。该本地复核没有重新审核原始 wire、全部 phase 文件及 `/proc` counter 字符串，边界在 review 中明示。外层原报告的 `independent_controller_cleanup=unknown` 保留，拥有的 stage／process group 已关闭不等于所有独立 Controller 会话均已证明关闭。

Mac lifecycle holder 原报告为 `remote_returncode=1`、`RemoteCampaignFailed`，临时 agent 已回收、目录及 socket 不存在。正常传回非零状态不会触发 Python 异常处理，因此原 `log_files` 没有 `holder.error.txt`；这不构成证据缺失。只在 Python 异常处理路径实际创建该 traceback 文件时采集。[Holder 原文件契约](../tools/x230/20261106/r36/holder-original-files.md)

## 归档下载后的原始证据补审

前述 observation／lifecycle review 保留它们生成时的汇总审查范围。完整归档下载、逐成员验证后，又使用本地已冻结的可信审计代码，完成单独的原始数据复核；归档中的脚本没有被执行，内部绝对路径没有被当作可访问文件路径。补审不改变 R36 的四项必选失败。[原始证据总复核](../tools/x230/20261106/r36/reviews/raw-evidence/raw-evidence-review.md)

| 补审范围 | 实际结果 |
| --- | --- |
| Observation wire 与资源计量 | 核验 2,672 个 frames／RPC envelopes、2,664 次工具调用、8 代 Controller 的 1,565 条 resource records；24 个 CPU cells 绑定实际 startup PID／birth ticks，24 份六主机 frozen job 副本匹配原 SHA。可信 analyzer 的完整对象及重新序列化的 62,873 字节与原 native analysis 逐字节一致。 |
| Lifecycle 原始计量 | 四轮可信原审计结果完全复现，44 份 phase clocks／counters 的 summary 完全复现；360 个 native RPC、372 个 transport frames、288 份 SSH streams、416 条 resource records、24 条 retained job records 的原件绑定通过。原 gates 除两处本地路径重定位外一致，仍为四项必选失败。 |
| 十二代 Controller 关闭补证 | 四代故意 SIGKILL 后为 `-9 / already_exited`，八代正常为 `0 / stdin_eof`。十二代均无 reader／sampler error、EOF 完整、unmatched responses 为 0，已观察代际的 survivor 列表为空；最终 wire／index／resource hash 与记录数一致。 |
| 测量期编译监测 | 从 observation 与 lifecycle 的原 ledger 独立复算，二者均通过原监测规则。 |

这是对原四轮中十二个明确 PID／birth-tick 代际及其本地 writer 的历史关闭补证。外层原始 `independent_controller_cleanup=unknown` 不改写；补证不等同于一次新的 live process inventory，也不扩展成所有可能的 SSH 或远端进程均不存在。全部补审只读取既有归档，未启动新负载。[Observation 原件复核](../tools/x230/20261106/r36/reviews/raw-evidence/raw-observation-review.md) · [十二代关闭复核](../tools/x230/20261106/r36/reviews/raw-evidence/raw-controller-closure-review.json)

## 未执行的阶段与有限停止边界

**异步 read 补充未执行；饱和取消／saturation 未执行。** 已封存的补充协议及工具只证明输入和代码已准备，不能产生测量、正确性通过、吞吐或最大并发结论。旧 helper 的部分 schema／scope 名称仍含 R25；它们保持原字节，本轮拒绝决定由 R36 外层报告和实际已执行阶段限定。[补充协议说明](../tools/x230/20261106/r36/supplement/README.md) · [冻结控制说明](../tools/x230/20261106/r36/control/README.md)

这次停止基于已测取舍与当前拒绝结果，未找到有现成证据支持的低风险、高收益遗漏项：

| 方向 | 已有证据与本次边界 |
| --- | --- |
| Release 编译配置 | 当前已为 O3、full LTO、单 codegen unit、panic abort、strip；R5–R7 及 R16–R18 报告已记录。重新打开这些开关不是新优化。 |
| Tokio workers 与客户端并发 | R16–R18 已做同一 R14 二进制的 workers=2 对 1／4 独立 ABBA。w1 的 C16 吞吐 −2.537%、CPU +2.364%，虽省约 1.4 MiB HWM；w4 的 C8 吞吐 −2.160%、HWM +11.550%。C16 的个别尾延迟收益是另一取舍，不是通用升级。 |
| glibc arena | R15 已诊断 default／1／2／4，并正式比较 default 与 arena1；大 receipt 内存下降伴随吞吐、CPU 或尾延迟成本。arena2／4 诊断不等于正式全矩阵，也未证明稳定额外收益。 |
| 哈希与读取 | R16 的 16／64／256 KiB 哈希 buffer 比较未支持放大；R19 已使用 ring SHA256，并记录该 X230 无 SHA-NI／AVX2。完整校验与 fsync 不能作为可省略的成本。 |
| 本轮成功路径缓存复制 | R36 保留验证和持久化边界，完成完整资格，但必选 lifecycle 失败，拒绝采纳。 |

历史 worker／allocator 结果属于当时基线和负载，不能证明 R24 在所有场景最优。面向 CPU 的编译变体、PGO／BOLT、更多 allocator 组合没有在本次检查的历史材料中提供可采纳收益；这也不证明它们无效。既有 `--runtime-audit-group-commit` 已启用；下一层是进一步的 durability／批处理重设计，以及 owner 分片或专用等待执行机制，涉及 ACK、锁顺序和取消／reap 契约，需要独立设计与实验。**本轮达到的是固定 X230、六机拓扑、操作分布和既有契约内的有限停止点，不宣称全局最优、Pareto 最优或所有可能优化已穷尽。** [历史核验](../tools/x230/20261106/r36/reviews/history-review.md) · [R15](X230_OPTIMIZATION_20261103_R15.md) · [R16–R18](X230_OPTIMIZATION_20261104_R16_R18.md) · [R19](X230_OPTIMIZATION_20261104_R19.md)

## 原件身份、复用与发布闭合

[本轮工具目录](../tools/x230/20261106/r36/README.md)保留工具源码、原 manifests、准备输入和独立审查。原冻结工具包中 17 份字节相同的历史工具通过固定 SHA 引用仓库原件，可用纯文件 materializer 恢复完整 75 文件工具包。完整资格日志、测试库存、CI、性能原始 JSON／RPC／资源记录与失败状态按固定 scope 归档；ELF、mutable target、私有 profile／SSH／凭据和 agent socket 正文明确为 metadata-only omission。打包与验证通过不改变性能拒绝结论。

第一次证据采集 `capture-01` 在创建归档前以退出 1 结束：native observation report 与四份 `resource-samples.jsonl` 触发 `decoded-scan-queue-exceeded`／`raw:json-scan-budget-exceeded`。原失败回执 `evidence-capture-01-export-failure.json` 的 SHA-256 为 `24ef364dc00258ad354ec5650950060ac8e91f823c6598d922b8a18452752332`。该失败保留。后续 `evidence-tools-02` 仅修复入队前的重复内容去重，扫描规则、深度及大小／节点预算保持不变；原 tools-01 不变。`capture-02` 已完成采集、下载及独立本地验证，这是证据工具修复，不重跑或改写 workload。

| 原件 | SHA-256 |
| --- | --- |
| `performance/observation-summary.json` | `a5a17eadb4d6a934fe464ccb1cb8dee5b32911355e294f25e3d93ad97024a246` |
| `performance/observation-native-analysis.json` | `b2695e1c9992b0b0a9b547ea2d64e4da6fa83e7b5616ebb294215849b470bda0` |
| `performance/observation-parent.json` | `d86577f327efb970588070c9c64f05942bd82ddff5613a11026d4448820c9299` |
| `performance/lifecycle-gates.json` | `243dd43cda85f1ad7700c9eba7f3cf4583edc6641cf4259447cbca71c648924e` |
| `performance/lifecycle-summary.json` | `6dd4723959fde86bcc41f2d466d74a800a32a7658f7f3f30d35a76737e9d5fca` |
| `performance/lifecycle-report.json` | `1ee73f9556b2ce0e139394e5add300fcf49c2ad985ed00eb16064e9f6842cebb` |
| `performance/lifecycle-parent.json` | `f5da48f7569240789a9c30d9661dd74ea797297fa6e12e715bc420316b00f020` |
| `rust-ci/report.json` | `60698a15516f8777eb59d435c116a84c72d2997c7516b68e8943d2648b7fc2e8` |
| `rust-ci/source-pr-ci-jobs-complete.json` | `86eee06a3812729a16b5b22f09cbfa0a1f088b1ee8db2bcbb6de038e440bc380` |

原始归档已下载，独立本地 verifier 通过：**9,447 个 payload 成员加 1 个 manifest、31 项明确 omission、44 份已观察 holder 文件**；成员／inventory／SHA 一致，原始输入未变，有界 raw／decoded 扫描无发现。该验证只建立归档及原件绑定，不把性能拒绝改成通过，也不替代逐条性能原始证据的专门审计。[原 export 回执](../tools/x230/20261106/r36/evidence/export-report.json) · [独立 archive verification](../tools/x230/20261106/r36/evidence/archive-verification.json)

| 已下载原件 | 字节 | SHA-256 |
| --- | ---: | --- |
| [r36-evidence-01.tar.xz](../tools/x230/20261106/r36/evidence/r36-evidence-01.tar.xz) | 3,961,240 | `30ff7e2dae12aa00a0048c9808610a76b17b4a37daa9de32dfab1fea06f2c9c9` |
| [export-report.json](../tools/x230/20261106/r36/evidence/export-report.json) | 4,989 | `a65780953c78c7cb7482f6565d84b31db4b483e87efddaf8dc353d0e7c6c7c69` |
| [archive-verification.json](../tools/x230/20261106/r36/evidence/archive-verification.json) | 4,314 | `190827cdfa65dedb634189616d6e0e272609acfe1ecba0e155fa33ef3892debb` |

实际采集与验证使用独立保留的 [evidence-tools-02](../tools/x230/20261106/r36/evidence-tools-02/README.md)。原 `evidence/verify_r36_evidence.py` 仍属于 tools-01，不冒充这次采集工具；复核命令见工具目录顶层 README。源码 `d3590733f6c301a91cb8f4fcc54ee5c3251a9530` 的 exact-head／prospective-merge CI 已验证；最终证据提交的实际 CI 将在发布后回读并链接至 [PR #106](https://github.com/TrillionniumFoundation/hepta-runtime/pull/106)，这里不预填未来提交身份或 CI 成功状态。
