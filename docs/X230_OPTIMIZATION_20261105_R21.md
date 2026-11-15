# X230 R20–R21：冷进程优化候选、完整资格与六机拒绝结论

**R21 组合候选不采用，继续保留已验收的 R19 源码。** 最终候选只在 `src/mcp/runtime/jobs.rs` 中延后 STATUS 和 CANCEL 的 `subprocess` 导入，共 7 行新增、2 行删除。两项组件通过固定 CPU 筛选，最终 fresh qualification、六机功能、C32 容量／恢复和四轮真实生命周期也通过；但 C1 吞吐下降 12.2922%、p95 上升 37.1637%，C8 p95 上升 18.2526%，没有满足正式回退门。完整 raw 离线复算已通过，结果与原汇总精确相同；本轮不会将候选应用到运行时源码。

本轮也测试了固定 4 KiB 和 64 字节的 request-hash 缓冲。两者都通过正确性检查，但小请求 CPU 回退超过事先约定的 2% 门槛，均被拒绝。最终候选不包含任何 hash-buffer 改动。

STATUS 的两个原生 Linux 场景测得 fresh-helper CPU 下降约 13%，但代码未变的 READ 同时下降约 6%。CANCEL 的两个原生场景分别下降约 8% 和 11%，它的 READ 对照却上升约 3%。这些数字支持继续验证延后导入这一机制，同时表明有限 ABBA 测量存在不可忽略的对照波动；它们不能直接换算为六机吞吐、常驻内存或最大并发能力的收益。

完整文件身份、原始包位置和各结果的来源列在附属 [evidence-identities.json](../tools/x230/20261105/r21/evidence-identities.json)。本文用短源码标识区分实验，不把长哈希表放入正文。

## 被测对象与证据链

基线是已发布的 R19 提交 `acdd07363cbff335e50c2944e02143d44ab03d6b`，正式对照使用 X230 上其有效 `qualification-02` 的实际产物。硬件、历史六机拓扑与资源解释沿用 [R19 报告](X230_OPTIMIZATION_20261104_R19.md)：ThinkPad X230、i5-3230M、2 个物理核／4 个硬件线程、约 7.46 GiB 内存。本轮实际 Python 为 3.12.3，内核为 Linux 6.8.0-142，Rust 为 1.95.0。计划不修改 governor、sysctl、生产服务或全局机器配置。

| 对象 | 源码关系 | 已取得的证据 | 当前范围 |
|---|---|---|---|
| R19 基线 `c908…` | 已发布源码 | 有效完整资格与历史六机验收 | 本轮 A 产物来源 |
| R20 中间态 `2f751c…` | R19 + STATUS 延后导入 | 352 个 fresh helper；完整资格；219 项输入绑定 | STATUS-only 已 qualified |
| R21 最终候选 `1f1f08…` | R20 + CANCEL 延后导入 | 228 个 fresh helper、66 个自有目标；组合链与最终完整资格已通过 | 最终六机性能门拒绝；完整 raw 离线复算通过 |
| 4 KiB／64 B hash-buffer | 独立组件方向 | 各 96 cells、102 stages；两次原门槛均拒绝 | 不进入最终源码 |

R20 正式六机工具曾准备、审查并安装，但没有执行。STATUS-only 中间态在正式性能测量前被组合后的 R21 取代；保留其完整资格与所有组件结果，避免再运行一次已经不打算采用的整链候选。

实际 [component-chain-01.json](../tools/x230/20261105/r21/component-chain-01.json) 绑定 `c908… → 2f751c… → 1f1f08…` 两段来源、两份真实 producer 语义报告、实际工具与计划，以及当前 R21 文件的完整字节。第一段只改变 `STATUS_CODE`，第二段只改变 `CANCEL_CODE`；其它 Rust 文本、READ／START 等嵌入式代码保持字节相同，六段 Python 去掉 import 后的 AST 相同。完整 [production.diff](../tools/x230/20261105/r21/production.diff) 可直接审阅。

这条链没有把早期冷进程测试改写为最终源码的直接测试：STATUS 的原测试对象是 `2f751c…`，CANCEL 的实际候选才是最终 `1f1f08…`。链内明确记录 `final_was_directly_coldprocess_tested=false`。creator、资格 launcher 和 verifier 共用冻结的链验证策略并重读实际文件；完整构建／测试日志审计、组件 raw 离线审计以及最终 Git 源码绑定是另行完成的证据层，不声称同一链策略有两套独立实现。

## 代码改动与行为边界

原 STATUS 和 CANCEL helper 在启动时就导入 `subprocess`，而常见 Linux 路径可直接使用 `/proc`、已有状态文件或 pidfd，并不需要该模块。候选将导入移到实际调用点：STATUS 的非 Linux `ps` 路径和 systemd 查询分支，以及 CANCEL 的非 Linux `ps` 路径。需要子进程的分支仍然导入并使用原模块；没有替换命令、调整超时、修改进程身份检查或取消信号策略。

这项改动针对每次调用都启动新 Python 解释器的 operator helper 路线。测量包含解释器启动和真实 helper 执行成本，不能解释为 Rust 函数本体的 CPU 降幅，也不覆盖 isolated jobctl 的执行成本。jobctl 源码没有改变，完整资格仍要求其新产物与已接受基线逐字节相同。

在正常 Python 环境下，固定语义矩阵的输出、错误、状态文件和资源关闭行为通过检查。另有刻意阻止未使用 `subprocess` 导入的环境边界：候选允许不需要该模块的 Linux 路径继续执行，基线可能在顶层导入时退出。这是延后导入带来的明确行为差异，不以“所有环境下行为完全相同”概括。

## STATUS 冷进程实测

实际执行一轮 ABBA、5 个场景、每 cell 16 次独立 fresh-helper 调用，共 20 cells／320 次计时进程；另有 15 对语义检查和 2 个依赖缺失边界进程，合计 352 个。每个场景每个 arm 有 32 次计时调用。原生 benchmark 直接运行从实际源码抽取的完整 PRIVATE 包装＋BOUND＋STATUS／READ 文本，计时版本没有模块诊断前后缀；systemd 与非 Linux `ps` 场景保留所需 mock，仅作诊断。

CPU 是串行启动并回收的 fresh child 的 `RUSAGE_CHILDREN` user+system 增量；wall 包括 `Popen`、通信与回收。下表为各 arm 的总量除以调用数，变化为 B/A−1；不是函数内循环微基准。

| 场景 | A CPU ms/调用 | B CPU ms/调用 | CPU 变化 | A wall ms/调用 | B wall ms/调用 | wall 变化 |
|---|---:|---:|---:|---:|---:|---:|
| completed STATUS | 59.367 | 51.599 | −13.085% | 59.931 | 52.177 | −12.938% |
| completed READ，未改动对照 | 45.326 | 42.557 | −6.108% | 45.997 | 43.130 | −6.232% |
| detached live STATUS | 55.307 | 47.984 | −13.241% | 55.852 | 48.559 | −13.059% |
| systemd mock，仅诊断 | 56.637 | 58.640 | +3.536% | 57.244 | 59.131 | +3.297% |
| non-Linux ps mock，仅诊断 | 55.576 | 56.768 | +2.144% | 56.161 | 57.314 | +2.052% |

两个相邻配对分别比较 round 1 的 B 对 round 0 的 A，以及 round 2 的 B 对 round 3 的 A。completed STATUS 的 CPU B/A 为 0.876874／0.861459，detached live 为 0.872549／0.862542。两条原生 STATUS 路径的聚合 CPU 均低于 0.95，两个配对均低于 1.0；READ 对照低于原先约定的 1.10，组件筛选通过。

READ 在两 arm 的执行脚本字节相同，却同样出现 CPU 与 wall 下降。因此不能把 STATUS 约 13% 的完整差异都归因于代码，也不直接用 READ 百分比相减当成经过证明的因果校正。mock 的小幅回退完整保留，不当作生产 systemd／Mac 性能结论。

独立 [cold offline audit](../tools/x230/20261105/r20/reviews/cold/x230-cold-offline-audit-01.json) 从全部 raw 进程记录、stdout/stderr、时钟端点、累计计数器和固定夹具重算结果，14 项检查通过。原 archive 的 840 个成员另经外部 manifest 核对大小、SHA、原路径与模式；其中语义夹具故意包含的非私有模式也按原记录验证，未用解包后的权限替代原始证据。该测量的 `ru_maxrss` 是累计 child 高水位观察，不能证明单 helper 的 RSS 或每次调用分配下降。

## CANCEL 冷进程与自有目标实测

CANCEL 对照直接使用 `2f751c…` 与 `1f1f08…`，固定三场景 ABBA，每 cell 16 次，共 192 个计时 helper；17 对语义检查和 2 个依赖缺失边界 helper 使总数达到 228。独立创建并清理 66 个自有目标，进程身份以 PID/start-ticks 绑定。已退出场景、真实 Linux owned-pidfd 取消，以及未改动 READ 对照分别保留完整原始证据。

| 场景 | A helper CPU ms/调用 | B helper CPU ms/调用 | CPU 变化 | A helper wall ms/调用 | B helper wall ms/调用 | wall 变化 |
|---|---:|---:|---:|---:|---:|---:|
| 已退出作业 CANCEL | 55.327 | 50.875 | −8.045% | 55.873 | 51.448 | −7.920% |
| Linux 自有 live 目标／pidfd CANCEL | 52.082 | 46.324 | −11.055% | 56.075 | 50.062 | −10.723% |
| READ，未改动对照 | 43.289 | 44.606 | +3.042% | 43.886 | 45.149 | +2.880% |

两个 CANCEL 场景的 CPU B/A 配对分别为 0.928040／0.909988 与 0.884830／0.894240。聚合均低于 0.95，每个配对均不超过 1.0；READ 聚合不超过 1.10，全部正确性与自有目标范围检查通过，原 screen 为 true。READ 在本次窗口向相反方向变化，再次提示组件百分比不等于无噪声的普遍收益。

helper 的 CPU 采样在目标进程 wait/reap 前结束；66 个目标的回收和 CPU 另行记录，不混入 helper 分子。离线审计核对 294 个不同 PID/start-ticks 身份；全部 helper 的 CPU 总量为 12.400775 秒，另行排除的目标 CPU 总量为 2.458898 秒。这两项是完整试验生命周期计数，不是表中三个 benchmark 场景均值的简单相加。观察到的 30,984 KiB child HWM 仍是累计高水位，不能当作单次取消的内存占用。

这些是真实 fresh helper 与受控自有目标的本机组件证据，尚不包含 SSH 端到端多机取消吞吐。完整 [CANCEL raw archive](../tools/x230/20261105/r20/evidence/cancelprocess-01.tar.gz) 含 1,918 个原始 probe 文件和 4 个冻结输入，另带 manifest。独立审计第 02 版的 15 项检查全部通过，重算 screen 为 true。

### 保留首次离线审计失败及修正

第 01 版离线 auditor 错把原生成功路径的模块导入断言扩展到了 mock 异常和提前退出路径，因而失败。原 producer 证据没有改变，性能没有重跑。第 02 版将该机制断言限定为原生成功路径和显式 blocked-import 边界，其余脚本、元数据、stdout/stderr、信号事件、关闭行为、夹具、时钟、统计和筛选检查保留。

具体而言，binding mismatch 可在 BOUND 中提前退出，尚未执行 CANCEL 顶层导入；非 Linux mock 又会主动导入模块以安装 mock。另有三个 B 异常路径在退出时观察到 `subprocess` 已加载，但现有记录没有定位由谁导入，不能把原因写成已证明的异常格式化行为。

原失败报告、两个 auditor 原文、差异、修正说明、两次 invocation 与 stdout/stderr 共 12 件材料由 [audit-evidence-manifest-01.json](../tools/x230/20261105/r20/reviews/cancel/audit-evidence-manifest-01.json) 全量列出。通过的第 02 版没有覆盖第 01 版。

## 被拒绝的 request-hash 缓冲方向

两个独立 bundle 分别测试 4,096 字节和唯一一次原则明确的 64 字节 follow-up。每个 bundle 都使用原六个固定场景、四个 ABBA blocks、96 个 fresh worker cells；加六个准备／检查阶段共 102 stages。每次有两个实际 Cargo tests，独立 check 进程检查六个 canonical fixtures 和七个 buffer 边界。离线各 225 项检查通过，全部 raw、源码和实际 reduced lock 闭合。

下表百分比为四个 block 内 B/A CPU 比率的中位变化，不是把两个 arm 的总体中位数相除。负数表示每次 digest 使用的 CPU 更少。

| 场景 | 4 KiB buffer | 64 B buffer | 原门槛及结果 |
|---|---:|---:|---|
| small_176 | +10.9944% | +5.1977% | 小／plain 输入至多 +2%；两次拒绝 |
| escaped_small | +5.9705% | +5.1194% | 至多 +2%；两次拒绝 |
| plain_64k | +5.9758% | −1.6945% | 至多 +2%；4 KiB 拒绝 |
| escaped_64k | −11.8187% | −15.6258% | 大 escaped 至少改善 5%；均通过此分项 |
| plain_1mib | +0.8723% | +0.5405% | 至多 +2%；均通过此分项 |
| escaped_1mib | −14.9052% | −10.6079% | 大 escaped 至少改善 5%；均通过此分项 |

两个大 escaped 场景在各自全部四个 block 中改善，但这不能覆盖小请求失败。64 B 的两个 small 场景更是四个 block 全部回退。按预先约定的停止规则，本轮结束这一方向，不继续扫 buffer 大小，也不采用条件性的 hash-buffer integration draft。

CPU 只计 digest loop，包含两 arm 共同的 full-hash 相等断言，排除启动、fixture、warmup 和资源读取。全部 worker 的生命周期 HWM 在 4 KiB 试验为 21,098,496 B，在 64 B 试验为 21,102,592 B，均没有建立 RSS 收益证据。不能从 fragment 减少单独推断栈初始化就是小请求回退的原因。四个 block 的完整方向和资源列表保留在 [4 KiB 结果](../tools/x230/20261105/r20/reviews/hash4096/RESULTS.md) 与 [64 B 结果](../tools/x230/20261105/r20/reviews/hash64/RESULTS.md)。

## 剩余同类路径与停止标准

本轮还检查了其余 helper 中的 `subprocess` 使用。START 的新作业路径实际需要 `run`／`Popen`，嵌入 supervisor 同样需要启动子进程；常规同键复用已在 Rust 中返回，不会重新执行这段 operator Python helper。READ 原本就没有该模块导入。因而没有把这次延后导入机械扩展到仍需模块的路径。具体范围见 [remaining-helper-imports-01.json](../tools/x230/20261105/r21/reviews/remaining-helper-imports-01.json)；这是一项源码检查，不是额外性能测量。

此前 workers=1／4、请求分配和 buffer 复用的实际取舍沿用 [R19 报告的停止点](X230_OPTIMIZATION_20261104_R19.md#当前停止点) 及其引用的 R16–R18 记录。本轮保持 workers=2、arena=1、完整请求 digest、nonce／UID／pidfd 校验、持久化顺序和容量策略。当前源码已经使用 ring SHA256，不能将换用 ring 再计为新优化。

停止标准是已经测量的候选通过预定正确性与性能门，或被其明确拒绝；已拒绝的两个 hash-buffer 方向不继续扫参数取样。本轮没有覆盖所有架构、业务分布或硬件组合，不能把这个有限停止点写成“再也无法优化”。本次组合候选已被下面的整链性能门拒绝，完整 raw 离线复算确认了相同结果。

## 完整资格与源码绑定

### 已完成的 R20 STATUS-only 资格

R20 在新的空 target 中完成 format、fmt-check、harness tests、all-targets/all-features strict Clippy、test-build、逐项 isolated tests、独立测试日志审计及 release 八个阶段，均退出 0。**1,637 passed／0 failed／33 ignored，1,670 selected，5 个 test binaries，0 test retries。** 33 个 ignored 项没有在此流程中执行；根 crate library 与五个测试 artifact 为 `fresh=false`。

完整资格阶段耗时 1,997.827 秒，随后独立验收耗时 13.020 秒，31 项检查全部通过。源码前／中／后 281 文件全等，219 个编译输入保持一致；实际 jobctl 新产物通过严格基线 SHA 与逐字节比较。新 runtime 与 driver 分别绑定本次实际产物，不根据源码变化小就推定二进制相同。

原 [R20 qualification archive](../tools/x230/20261105/r20/evidence/qualification-01.tar.gz) 保留 3,362 个源码／收据／完整日志文件和 embedded manifest。8 个 ELF 没有作为二进制内容入包；导出时的稳定全文件 SHA，已在离线 sidecar 中逐项对齐 acceptance 的 3 个 release 与 5 个 retained test binaries 的 exact path、SHA 和可用 size。这是实际远端字节身份与原验收的绑定，不声称在本地复现 ELF。

独立 [qualified-source-binding-01.json](../tools/x230/20261105/r20/reviews/qualification/qualified-source-binding-01.json) 核对七份 219 输入 map、三份 281 全树快照及实际产物，10 项检查通过。R20 `src` 树重新算得 `7e5e1984…`，其 218 个未改输入的 SHA256↔Git blob 对应关系来自固定 R19 提交和已发布完整证明，改变的 jobs.rs 本地重新哈希。该证明没有冒称重新下载了所有 218 个叶字节，也不绑定尚未产生的最终发布 commit。

R21 沿用成功的显式构建环境白名单，四种 Cargo／rustc wrapper 环境键全部缺席，不设为空字符串；这样保留 R19 已诊断并验证的构建身份约束。仍使用冻结原 qualifier、offline／locked Rust 1.95、jobs=2，以及原测试 runner／auditor，不因资格耗时而跳过阶段。

### R21 最终资格与完整离线复核

R21 的最终源码经真实 component chain 绑定后，在新的空 target 中完成八阶段完整资格；控制进程于 2026-11-05 02:19:28 UTC 成功结束。实际 qualification 耗时 1,913.675 秒，独立验收 12.003 秒；31 项 checks 全为 true，源码 281 文件前／中／后全等、219 编译输入一致，jobctl 新产物与基线相同。此次 R21 自己的测试记录为 **1,637 passed／0 failed／33 ignored／1,670 selected，0 retries**，没有借用 R20 的计数。qualification、verifier 及记录的 toolchain 子进程均已 wait/reap，原 PID 和进程组已不存在。

原始 archive 保留 3,364 个 payload 文件和 embedded manifest，8 个 ELF 的完整远端字节身份逐项匹配实际 acceptance；归档共 1,483,427 B。正式测量结束后以 46 个固定 version 分片完整回传，SHA 全等，0 transport errors／retries。安全解包逐项核对 3,365 个成员及 8 个省略 ELF 身份。

随后用冻结原 isolated-test audit 函数重新读取 1,647 条命令和 3,294 份 gzip stdout／stderr，完整枚举、精确判决和九项确定性字段均与原 audit 相同。离线适配仅映射两个确切文本路径，并为五个已省略 ELF 提供与 actual acceptance 对齐的完整远端 SHA 见证；原 audit 与支持函数体未改，未执行测试，也没有声称本地重新哈希 ELF。六项 raw-replay 检查通过；[可读摘要](../tools/x230/20261105/r21/reviews/qualification-raw-replay-summary-01.json) 指向 local-review 包中保留的完整 1,494,181 B 结果。

最终 [qualified-source-binding-01.json](../tools/x230/20261105/r21/reviews/qualified-source-binding-01.json) 的 12 项检查全部通过，独立重建两段 component chain，核对七份 219 输入 map、三份 281 全树快照和三个真实 release 产物。候选 `src` 树为 `5f814d4f…`，其中 218 个未改输入的 SHA256↔Git blob 关系来自已发布的固定 R19 证明，改变的 jobs.rs 从完整候选字节重新计算。这个 qualified 证明描述的是被拒绝的 R21 候选，不是本次仍保留的 R19 源码树。

| 项目 | R21 实际值 |
|---|---|
| 完整资格与独立验收 | 八阶段退出 0；31 checks 通过；qualification 1,913.675 s／verifier 12.003 s |
| 测试 passed／failed／ignored／retries | 1,637／0／33／0；selected 1,670，5 个 test artifacts |
| runtime／jobctl／driver 身份 | 实际完整 SHA 分别为 `770957…`／`61c902…`／`4fb2c2…`；完整身份见索引 |
| 最终 qualified source tree | 候选 `5f814d4faa80b87cfb3a34ca38275664444c0883`；12 项独立绑定检查通过，候选未采用 |
| 原始 archive 与离线重算 | 3,364 payload＋manifest；1,647 commands／3,294 gzip 原流完整复核；全部通过 |

## 六机验收：固定口径与实际结果

正式对照为 R19 A → 最终 R21 B，固定历史六台主机 ai395、mac、main、pocket4、rog、x230。历史拓扑中的 main 是独立 Linux 机器，不能替换成连接器当前同名别名。workers=2、`MALLOC_ARENA_MAX=1`，资格结束及自有进程回收后按原计划静置 90 秒。完整 [measurement-plan-01.json](../tools/x230/20261105/r21/measurement-plan-01.json) 在正式测量前冻结；计划值和实际结果在本节明确区分。

### 已完成作业的 native observation

实际按 ABBA × C1/C8/C16 完成 12 cells，每 cell 192 measured＋24 warmup，status/read 在六个 host 间平衡。实际计数为 2,304 measured、288 warmup 和 72 preflight／restart，共 2,664 次调用；warmup 与 preflight／restart 不进入 measured 成功吞吐分母。每个 arm／并发档的成功 rate 用成功调用总数除以 cell 耗时总和；p95/p99 合并原延迟后取 nearest-rank。CPU 是同一 controller PID/start-ticks 的同步计数器差，不包含 SSH、远端 Python 或整个集群。

原有限样本筛选要求三个并发档均满足 B/A 成功吞吐 ≥0.95、pooled p95 ≤1.10，所有正确性、恢复及来源门通过。C8 为主工作点；p99 和两个配对的全部方向仍须报告。该门槛不是统计显著性或非劣性置信区间，也不能用聚合过门掩盖某个配对回退。

正式 R19 A → R21 B 对照已完成，所有原始调用与恢复正确性检查通过。以下结果已经完整 raw 离线重算；七个冻结原分析入口均退出 0，结果与原生汇总 JSON 精确相同，原 payload 保持不变。固定吞吐下限为 B/A ≥0.95，p95 上限为 B/A ≤1.10。

| 并发 | A 调用/s | B 调用/s | 吞吐变化 | A controller CPU ms/调用 | B controller CPU ms/调用 | CPU 变化 | 该档性能门 |
|---|---:|---:|---:|---:|---:|---:|---|
| C1 | 4.1639 | 3.6520 | -12.2922% | 130.234 | 131.380 | +0.8798% | 拒绝 |
| C8 | 23.4385 | 22.8027 | -2.7125% | 72.344 | 73.073 | +1.0079% | 拒绝 |
| C16 | 23.3954 | 23.0324 | -1.5518% | 73.620 | 72.083 | -2.0870% | 通过 |

| 并发 | A p95 ms | B p95 ms | p95 变化 | A p99 ms | B p99 ms | p99 变化 |
|---|---:|---:|---:|---:|---:|---:|
| C1 | 305.869 | 419.541 | +37.1637% | 446.819 | 754.941 | +68.9591% |
| C8 | 413.784 | 489.310 | +18.2526% | 461.080 | 605.171 | +31.2507% |
| C16 | 791.625 | 848.851 | +7.2289% | 842.225 | 1679.704 | +99.4364% |

C1 的吞吐和 p95 均失败；C8 吞吐仍在 −5% 范围内，但 p95 超过 +10%；C16 通过原吞吐／p95 门，不过 p99 仍上升约 99.44%。p99 并非采用门槛，其不利结果仍完整报告。

| 并发 | 配对：B round / A round | 吞吐变化 | controller CPU 变化 | p95 变化 | p99 变化 |
|---|---|---:|---:|---:|---:|
| C1 | 1 / 0 | -8.8545% | +1.2515% | +39.2013% | +1.8070% |
| C1 | 2 / 3 | -15.5664% | +0.5151% | -0.9755% | +115.0433% |
| C8 | 1 / 0 | -6.0889% | +1.7217% | +31.5374% | +60.7093% |
| C8 | 2 / 3 | +0.8355% | +0.2890% | -2.2696% | -4.6114% |
| C16 | 1 / 0 | -4.6633% | -2.2631% | +30.3879% | +138.7526% |
| C16 | 2 / 3 | +1.7266% | -1.9108% | -0.3239% | -3.4810% |

C1 两个相邻配对的吞吐均下降；C8／C16 的吞吐和尾部配对方向不一致。B 的各档两轮 rate 跨度约为 4.99%、5.08%、5.36%，A 分别为 2.82%、2.18%、1.27%。C1 的 pooled p50 只上升 0.31%，但 B 最大延迟为 7,689.391 ms，A 为 1,156.678 ms；这些是原样本的分布观察，不足以单独定位网络、主机负载或代码原因。所有样本均保留，没有删去慢调用、改门槛或重跑以取得另一组结果。

最大 B 延迟已定位到 round 2 的 pocket4 `process_read`：7,689.390513 ms，RPC id 41，job `1a16a40534e-b1270-4`，开始于 2026-11-05T02:26:58.208766+00:00。其原 transport 帧位于 `round-2-B/first/transport-responses.jsonl` 的 offset 24,879，长 615 B；原帧完整 SHA 与提取字节均已核对。READ helper 在该候选中没有改动，但当前证据没有定位这次延迟的原因，不能据此排除该样本或归因于网络。A 的最大值来自 round 0 的同一主机 `process_status`。两个调用均成功、没有自动重试；具体原帧和身份见 [C1 maximum identities](../tools/x230/20261105/r21/reviews/c1-max-identities-01.json)。

`native_regression_screen_passed=false` 与整体 `passed=true` 同时出现是预定语义：后者说明功能、来源和清理阶段完成，性能拒绝仍继续执行剩余容量与生命周期检查；它不表示可以采用候选。

这条 workload 测量已完成作业的 observation 调用，不等于启动新作业吞吐。为覆盖实际 start/live/cancel，本轮另有下述有限生命周期对照。

### C6 实际生命周期 ABBA

实际完成四轮 A/B/B/A，每轮六台主机各创建一个新 job，合计 24 个新 job；不是四个 ABBA blocks。四轮 canary、四份原恢复 auditor 和最终聚合均通过，完整 raw 离线复算重复得到原结论。新启动、同键复用、live status/read、取消、transport 中断和 controller 重启恢复都保留原夹具与清理策略；记录的每 host execution count、终态不变和自有资源回收证据完整通过。

phase sidecar 在整个六 host 并行 phase 外记录 monotonic 起止与同一 active controller PID/start-ticks 的原始 CPU 快照。CPU 只在前后进程身份相符时计算；prepare 明确为不可用。sidecar 写入位于计时后。

每 phase 完成 6 个 host；时间包含该 phase 的确认、原有有界轮询与独立 SSH 检查。原 aggregator 的 phase 比较是两轮算术均值，不与 native 的汇总吞吐公式混用。A 列顺序 0、3；B 列顺序 1、2。两配对分别 B1/A0、B2/A3。

| phase | A 秒（0、3） | B 秒（1、2） | 均值变化 | 配对 1 | 配对 2 |
|---|---|---|---|---|---|
| prepare | 0.809697, 0.697212 | 0.862558, 0.807930 | +10.855% | +6.528% | +15.880% |
| launch | 0.948218, 0.893383 | 0.926285, 0.754608 | -8.727% | -2.313% | -15.534% |
| before_crash_running | 1.776890, 1.831048 | 1.975479, 1.852225 | +6.091% | +11.176% | +1.157% |
| after_transport_running | 1.369922, 1.423472 | 1.449625, 1.368358 | +0.880% | +5.818% | -3.872% |
| after_crash_running | 2.004420, 1.938031 | 2.008023, 1.833884 | -2.550% | +0.180% | -5.374% |
| same_key_after_crash | 0.873751, 0.786653 | 0.949342, 0.770774 | +3.596% | +8.651% | -2.019% |
| concurrent_cancel | 0.890000, 0.790723 | 1.014593, 0.758409 | +5.490% | +13.999% | -4.087% |
| terminal | 1.467991, 1.226261 | 1.482026, 1.203501 | -0.324% | +0.956% | -1.856% |
| terminal_after_restart | 2.215094, 1.904938 | 2.119388, 1.788058 | -5.160% | -4.321% | -6.136% |
| same_key_after_cancel | 0.829444, 0.733330 | 0.919318, 0.720720 | +4.944% | +10.835% | -1.720% |
| cancel_after_terminal | 0.902128, 0.705433 | 0.792357, 0.702041 | -7.039% | -12.168% | -0.481% |

#### 生命周期 controller CPU

单位为整段 phase 的 controller CPU 秒；不是远端 Python helper CPU，也不是六机 CPU 总和。计数在 phase 前后读取并包围整个窗口；prepare 没有活跃 controller，所以为不可用。该机器原计数为 100 ticks/s，短 phase 的 0.01 秒量化需要保留。每 native call 的原值也在 JSON 中。

| phase | A CPU 秒（0、3） | B CPU 秒（1、2） | 均值变化 | 配对 1 | 配对 2 |
|---|---|---|---|---|---|
| prepare | —, — | —, — | — | — | — |
| launch | 0.050, 0.040 | 0.050, 0.050 | +11.111% | +0.000% | +25.000% |
| before_crash_running | 1.070, 1.020 | 1.100, 1.070 | +3.828% | +2.804% | +4.902% |
| after_transport_running | 0.940, 0.920 | 0.910, 0.950 | +0.000% | -3.191% | +3.261% |
| after_crash_running | 1.120, 1.100 | 1.080, 1.070 | -3.153% | -3.571% | -2.727% |
| same_key_after_crash | 0.030, 0.030 | 0.030, 0.030 | +0.000% | +0.000% | +0.000% |
| concurrent_cancel | 0.030, 0.030 | 0.040, 0.030 | +16.667% | +33.333% | +0.000% |
| terminal | 0.940, 0.850 | 0.860, 0.840 | -5.028% | -8.511% | -1.176% |
| terminal_after_restart | 1.180, 1.130 | 1.120, 1.070 | -5.195% | -5.085% | -5.310% |
| same_key_after_cancel | 0.030, 0.040 | 0.030, 0.050 | +14.286% | +0.000% | +25.000% |
| cancel_after_terminal | 0.030, 0.030 | 0.030, 0.030 | +0.000% | +0.000% | +0.000% |

实际合计 24 个新 job、48 次同 key 查询、48 次取消；四轮各有 90 个 native calls 和 36 个独立 SSH calls。这是本次实际计数，没有将 90 设成通用轮询不变量。一次 ABBA、每 arm 两样本，不能据这些 phase 均值宣称最大持续启动吞吐或统计显著的整体提升。

launch 的 wall 均值下降 8.727%，但该 phase controller CPU 均值上升 11.111%；concurrent_cancel wall 均值上升 5.490%。这些混合方向、短窗口与每 arm 两个样本不足以形成全面性能收益，不能覆盖前述 native 失败门。

### C32 突发、资源与恢复

两次 burst 均使用此次 qualified R21 artifact；成功与拒绝分别计量：

| burst | 窗口秒 | 成功 / capacity refusal / other | 全完成 calls/s | 成功 calls/s | 拒绝 calls/s | controller CPU ms/attempt |
|---|---|---|---|---|---|---|
| 0 | 0.797516682 | 16 / 16 / 0 | 40.125 | 20.062 | 20.062 | 36.5625 |
| 1 | 0.737750199 | 16 / 16 / 0 | 43.375 | 21.688 | 21.688 | 36.5625 |

总计 32 成功、32 capacity refusal、0 other error；两 burst 均完成 drain/recovery，另有 96 次计划的 post-drain 观测。32 个 pending 客户端 RPC 不代表 32 个内部 pool identities：exact pool identity peak 未观测到，不据此推断内部同时准入 16。拒绝不算成功吞吐，CPU/attempt 也不能按成功/拒绝类归因。

| burst | 成功 p95 ms | capacity refusal p95 ms | other error |
|---|---:|---:|---:|
| 0 | 788.445451 | 45.759556 | 0 |
| 1 | 728.691484 | 48.485177 | 0 |

每类每 burst 只有 16 个样本，nearest-rank p95 与最大值相同。全部 202 次计划调用和 204 个 transport frames 已独立复核；96 次 post-drain 是新的计划请求，不是自动重试。以下资源表来自 native observation 的四轮 ABBA，不是 C32 burst；主 controller 与 restart controller 分列：

| round / arm | controller 阶段 | sampled VmHWM KiB | sampled controller RSS max KiB | sampled tree RSS max KiB | sampled controller FD max |
|---|---|---|---|---|---|
| 0 / A | shutdown | 17520 | 17520 | 108624 | 96 |
| 0 / A | restart_shutdown | 14788 | 14788 | 62400 | 55 |
| 1 / B | shutdown | 17468 | 17468 | 124252 | 98 |
| 1 / B | restart_shutdown | 14948 | 14948 | 69568 | 55 |
| 2 / B | shutdown | 17608 | 17608 | 109596 | 95 |
| 2 / B | restart_shutdown | 15164 | 15164 | 69556 | 55 |
| 3 / A | shutdown | 17508 | 17508 | 108832 | 90 |
| 3 / A | restart_shutdown | 14900 | 14900 | 69828 | 55 |

主 controller VmHWM 两轮均值 A=17514.0 KiB，B=17538.0 KiB，差 24.0 KiB（+0.137%）。这组数据没有建立 RSS 节省。

100 ms 采样可能漏掉短命或重父进程，tree RSS 非同时求和且可能重复计共享页。PID 消失、权限不足、字段缺失等原错误计数及 trace 身份均保留在 JSON 和完整 raw 中；不可把缺失当零。重启 controller 单列，不混入主 controller 的两个样本。没有量化每调用磁盘 I/O 节省，日志/归档/返回字节数只表示证据或输出大小。

完整的 12 个 native 计时窗口、44 个 lifecycle phase 原计数器、资源缺测计数与机器阶段快照保存在 [campaign-metrics-01.json](../tools/x230/20261105/r21/reviews/campaign-metrics-01.json)，便于复查汇总公式与范围。主 controller 最高采样 RSS 约 17.2 MiB，主阶段 tree RSS 约 106.1–121.3 MiB；后者包含子进程、非同一时刻采样且共享页可能重复，不能当作精确独占占用。

## 保留的开发、导出和传输异常

以下事件均单独保留，不计入性能自动重试，也不以重新运行 workload 获取替代样本。

- 冷进程证据初次并发读取所在 exec cell 在等待时变为不可用，原响应和内存 store 未恢复；原因未知。随后按相同固定 file version 以较小分片重新读取，最终 archive／外部 manifest 大小与 SHA 全部闭合。
- R20 qualification 下载在 offset 1,245,184 的一次读取返回非 JSON 文本，解析失败发生在保存完整原返回之前。原请求和 parser exception 保留，但完整错误原文丢失，不能据此断定是 timeout 或远端文件问题。同版本只读重取后完整 archive 通过；后续读取先持久化 raw response 再解析。
- 一次本地 exec-server 断连影响的是已返回远端启动收据的本地落盘，原远端 job 没有重复启动；恢复后查询同一 job 的权威终态并保存收据。
- 4 KiB 组件第一个 exporter 将普通证据的 nlink=1 规则误用于 Cargo target ELF，因此在建输出目录前退出 1。修正版只对明确选定的 compiler ELF 允许稳定 hardlink 哈希见证，其余源码／证据仍要求单链接；原失败、两版工具与成功输出均保留。这不是组件正确性或性能失败。
- CANCEL 第 01 次离线审计失败和第 02 次有限修正按前文完整保留；未改 producer、原源码或 raw，也没有重跑性能。
- R21 一次 whole-file 读取因超过工具单文件上限被拒绝，随后通过固定版本 binary 分片取回；一次本地 JSON 嵌入 Python 的布尔字面量错误由已保存 raw response 恢复，未重复启动远端工作。另一次 Git blob 等待调用在 dispatch 前中断，随后继续等待同一 cell 并确认原操作成功；未重复写入或移动分支。原错误及更正记录保留。
- CANCEL 下载在没有在途调用时暂停，让独立 64 B 性能窗口先结束，再继续原 file version。十个分片最终全部核验，0 transport rereads；这是取证调度，不是实验重跑。

开发期间取得的一个本地 jobs.rs 副本曾截断为 147,456 B，原完整文件为 186,456 B；该副本被保留并恢复核验，没有用于正式候选。最终组合链要求各源完整 SHA、大小与逐段源码差分；相关本地失败及更正属于开发证据，不能省略成“所有准备尝试一次成功”。

## 归档与发布状态

R20 组件与中间资格的原始证据按四类、五个不可变 archive 保存，复用原字节，不把其数千个展开成员再重复提交为 Git 文件。

| 类别 | 仓库 archive | 原始内容范围 |
|---|---|---|
| 中间完整资格 | `r20/evidence/qualification-01.tar.gz` | 3,362 个文件＋embedded manifest；8 ELF 只保留完整身份见证 |
| STATUS 冷进程 | `r20/evidence/coldprocess-01.tar.gz` | 840 个 payload；外部 `coldprocess-01.manifest.json` 必须一起保留 |
| CANCEL | `r20/evidence/cancelprocess-01.tar.gz` | 1,922 个 payload＋embedded manifest |
| 拒绝的 hash 方向 | `r20/evidence/request-hash-4096-01.tar.gz` | 332 个 payload＋export manifest |
| 拒绝的 hash 方向 | `r20/evidence/request-hash-64-01.tar.gz` | 332 个 payload＋export manifest |

表中路径均相对 `tools/x230/20261105/`。可读原计划、工具源码、独立审计与修正材料另行选择；本地运输分片和同内容 base64 不作为第二套原始实验数据重复提交。所有原 archive、外部 manifest 与独立收据通过索引关联，索引保留完整 size／SHA256／Git blob 身份。

R21 新增的四类包与 R20 证据一并闭合：

| 类别 | 仓库 archive | 原始内容范围 |
|---|---|---|
| 最终完整资格 | `r21/evidence/qualification-01.tar.gz` | 3,364 payload＋manifest；8 ELF 完整远端身份；全部原测试流 |
| 六机正式 campaign | `r21/evidence/campaign-01.tar.gz` | 5,379 payload＋manifest；9 ELF 完整远端身份；四个原证据树、全部 transport、资源与 lifecycle |
| Mac holder | `r21/evidence/holder-01.tar.gz` | 28 payload＋manifest；实际 holder/bootstrap、全部原日志、安装与回收收据 |
| 本地 review | `r21/evidence/local-review-01.tar.gz` | 冻结 exact inventory；原开发失败、转运收据、离线工具与完整审计、最终 orchestration |

资格、campaign 和 Mac 包分别为 1,483,427 B、5,204,365 B 和 15,653 B；完整 SHA、Git blob、全部被选路径和本地 review 成员在索引中绑定。离线 qualification 的 9 项 export、6 项 raw-replay、12 项 source checks 全通过，campaign 的七个冻结分析入口与原汇总相等，Mac 独立审计 24 项检查通过。三包固定 version 下载分别为 46、80、1 个分片，均 0 transport errors／retries。没有重跑正式性能试验。

Mac holder 的 SSH foreground 命令成功返回，所持 agent 已 wait/reap，自有 agent 目录和 socket 的退出后不存在记录也由随后导出独立观察。Mac footer 保留远端 `passed=true` 与 `native_regression_screen_passed=false`，但没有 X230 report SHA；[orchestration-final-01.json](../tools/x230/20261105/r21/reviews/orchestration-final-01.json) 将真实 Mac report／bootstrap 身份、footer 路径与另行读取的 X230 完整 control report 跨包绑定，不声称 Mac exporter 独立读取过 X230 report。五个 campaign 外层阶段、四轮 lifecycle 和全部记录的自有子进程完成并回收，没有在途远端任务。

凭证、私钥、agent socket、target ELF／object／rlib 与重复展开目录不入证据包。ELF 仅按明确的原始全文件身份见证关联，没有冒称本地复现机器码。离线工具、原计划、原始归档、代码差分与精确执行命令可从 [README](../tools/x230/20261105/r21/README.md) 和索引逐项追溯。

## 最终决定与可复查停止点

**拒绝 R21 STATUS＋CANCEL 组合候选，拒绝两个 hash-buffer 候选，保留已验收 R19。** 组件 CPU 的局部改善没有转化为通过原门槛的六机端到端表现；本轮也没有建立稳定内存下降或最大并发能力增长。原生 observation 在本次 A 的 C8／C16 约为 23.44／23.40 successful calls/s，提高客户端并发没有继续增加该 workload 的吞吐，且 C16 的 p95 更高；这限定于当前六机和当前 workload，不是整个系统的理论上限。

本轮向现有 [draft PR #87](https://github.com/TrillionniumFoundation/hepta-runtime/pull/87) 添加报告、原始证据、工具和拒绝记录，编译源码仍保持 R19：`src` 树 `3aa8c9aadbf42b6a0ebdac3954bd1e64b4055e20`，jobs.rs 的 SHA256 `c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9`。qualified 候选树 `5f814d4f…` 只存在于证据关系中，候选 diff 未应用到源码。本次 publication selector 只允许 `docs/` 和 `tools/` 条目；创建实际 tree 后再以 Git 根树身份、固定 R19 发布证明和 ref 读回核对源码保持不变。自身尚未生成的 commit SHA 不写入同一提交的文件，实际发布身份在 PR 中记录。

当前停止点来自真实组件实验、完整资格、六机正式 ABBA、容量／生命周期恢复和完整离线审计。所有拒绝、控制波动、失败的准备尝试和不利尾部指标均保留；没有改变容量、完整 digest、nonce／UID／pidfd、持久化或取消保证，没有修改机器 governor、sysctl 或生产服务。后续若出现新的实际 workload、硬件、profile 或可验证机制，可以以新的预定试验继续；现有证据不支持宣称“永远不能再优化”。
