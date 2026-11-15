# D1 C1 结果字段与计算口径

状态：仅只读冻结源码形成的结果阅读指南。未执行 parser、测试、采样或主机请求；没有实际 C1 结果，也不新增验收门槛。解释结果仍以原 parent、native audit、holder 和清理回执的既有闭合结论为前提。任何原测量失败按已冻结协议处理，不筛选成功请求做成本解释、不扩 C8、不重跑。

## 1. 文件别名与索引

以下路径均相对 `/home/qian/hepta-runtime-phase-cost-20261106-d1/`：

| 别名 | 原文件 |
|---|---|
| P | `c1-campaign-01/report.json`，parent 最终闭合状态 |
| D | `c1-campaign-01/summary.json`，原 diagnostic_result 输出 |
| N | `c1-observation-01/report.json`，原四轮逐调用报告 |
| I | `c1-observation-01/independent-summary.json`，已执行的原 native audit |
| A | `c1-adapter-evidence-01/adapter-report.json` |
| T | `A.traces[t].trace.path` 指向的原 `phase-cost.trace.jsonl` |

`N.rounds[r]` 的 r=0,1,2,3 对应 OFF/ON/ON/OFF，即 A/B/B/A；两臂是**同一个已资格 feature ELF**，并非两个优化版本或 ordinary ELF。

`A.traces[2*r]` 是该轮 first controller；`A.traces[2*r+1]` 是 restart controller。因此 measured ON 只来自 `A.traces[2]` 和 `A.traces[4]`，并进一步筛选 `selected_on_requests[].category == "measured"`。

完整原协议对应每个 measured cell 192 条、每个 host×operation 16 条；四轮 measured 共768，ON measured 共384。每轮另有24 warmup、6 preflight、12 restart。ON first trace 含222条请求，ON restart trace含12条；不能用整个 trace 总量除以192。OFF trace 的 `requests == []` 是关闭记录的设计，不能解释为 OFF 没有 CPU 消耗。

## 2. 直接可读的准确路径

| 目的 | JSON 路径 / 筛选 | 单位与作用域 |
|---|---|---|
| 单条 ON measured 的已记录同步 CPU | `A.traces[t].selected_on_requests[j].recorded_synchronous_cpu_exclusive_ns`，t∈{2,4} 且 category=measured | ns；扣掉直接同步子 span 后的请求内总和 |
| 同一请求标识与分组 | 同行的 `native_request_id`, `slot`, `host`, `operation`, `rpc_id`, `job_id` | slot 只在单个 trace 内有效；job_id 在多次观察中重复，不是请求唯一键 |
| 内层请求 wall | 同行 `request_wall_ns` 和 `trace_request_interval_monotonic_ns` | trace 内层 request span；不是整个客户端 RPC latency |
| 原 RPC/测量窗口 | 同行 `call_interval_monotonic_ns`, `cell_interval_monotonic_ns` | trace request 被证明包含于原 RPC interval；RPC 包含于原 cell interval |
| 原 cell 192 条请求 | `N.rounds[r].cells[0].rows[]` | `elapsed_ms`, `host`, `tool`, `rpc.request_id`, `start_monotonic_ns`, `end_monotonic_ns` |
| 请求队列三段 wall | selected请求的 `derived_queue_spans.channel_wall_ns`, `pending_until_initial_global_grant_wall_ns`, `dispatch_schedule_wall_ns` | ns；原 marker 不唯一/缺席时为 null，不是0 |
| 整个 trace 的 phase 分布 | `A.traces[t].trace_summary.phase_thread_cpu_exclusive[phase]`；另有 `phase_thread_cpu_inclusive[phase]`、`phase_wall_nonadditive[phase]` | 每个 phase 的 event/span 分布：`count,sum_ns,median_ns,p95_nearest_rank_ns,maximum_ns`；包含该 controller 的 preflight/warmup 等 |
| 直接原审计的吞吐/延迟/CPU | `I.cases[0].arms.A/B` 与 `I.cases[0].change_percent`；D中同值在 `original_raw_cases[0]` | 已按原两轮合并计算，见下节 |
| controller 生命周期 RSS | `N.rounds[r].shutdown.resources.peaks.controller_rss_kib`；restart 用 `restart_shutdown` | KiB；first 生命周期峰值，包含启动、preflight、warmup、measured 和关闭，不是纯 measured 峰值 |
| 同一资源的原 audit 路径 | `I.resources[]` 按 `round=r,phase="shutdown"` 或 `"restart_shutdown"` 选；再取 `observations.peaks.controller_rss_kib` | D中同数组为 `original_resource_evidence` |

adapter 已用原 transport frame 的字节范围/SHA、JSON RPC id、响应 canonical SHA 和 `result._meta["io.hepta.runtime/request-v8"].request_id` 绑定 native request id，再检查 host/operation 和全部时间包含关系。优先使用已绑定的 selected 行；跨 trace 联接时保留 controller pid/start_ticks/trace 身份，不能仅凭 slot 或 job_id。

## 3. 同步 CPU：绝对值、占比和 phase 排名

令 M_r 为该轮192条 selected measured请求，S_i 为其 `recorded_synchronous_cpu_exclusive_ns`。

- 单请求已记录 CPU：S_i/1000 μs，或 S_i/1e6 ms。
- 该轮平均每请求已记录 CPU：ΣS_i / 192；两个 ON 轮合并为两轮总和/384。也应同时保留两轮各自值、host 和 operation 分组。
- 请求级 p50/p95：对这些 S_i 本身排序。nearest-rank p95 取第 ceil(0.95*n) 个；这与 parser 的 p95 定义一致。不要把某个 phase 的 event p95 当作请求总 CPU p95。

**当前 JSON 没有“仅 measured 的 per-request phase CPU 明细”。** `trace_summary.phase_thread_cpu_exclusive` 是整个 trace 的 phase汇总。需要 measured phase 排名时，按已保存原 T 事件作下述派生，不能直接取 whole-trace `sum_ns`：

1. 用 selected measured 请求的 `slot` 选择原事件行 `type=="event"` 且 `event.request==slot`；只统计 `thread_cpu_start_ns != null`。
2. 每个 span 的 inclusive CPU 是 `thread_cpu_end_ns - thread_cpu_start_ns`。
3. 沿 `event.parent_sync_span` 找**直接**同步 CPU 子 span，exclusive CPU = 本 span inclusive − 直接子 span inclusive 之和。父子必须同 request/thread、区间嵌套；这就是原 parser 已冻结算法。
4. 按请求与 `event.phase` 汇总 exclusive CPU，再在 M_r 上汇总。phase 占比 = 该phase measured exclusive总和 / ΣS_i ×100%。

该百分比的标签必须是**“占已记录同步 CPU”**。它不是占整个 controller CPU、远端 CPU 或端到端 wall 的比例。phase per-request均值可用phase总和/192；若看phase per-request p95，应先把同一请求多个同phase span合并，不能用原每-event分布替代。

`S_i / request_wall_ns` 可以另报为“记录CPU时间/request wall比”，但不是完整CPU覆盖率，也不是纯单线程忙碌率；跨线程CPU相加时不能预设其上限为100%。

计算差值先保留整数ns，再换算μs/ms。不要把原大整数经JavaScript Number重新序列化。

## 4. OFF/ON 吞吐、controller CPU 和 RSS

### 吞吐和 controller CPU

直接读 `I.cases[0].arms.A/B`：

- `calls_per_second` = 两轮 calls总数 / 两轮 `seconds` 总和；**不是两轮 RPS 的算术平均**。
- `controller_cpu_ms_per_call` = 1000 × 两轮 `controller_cpu_seconds` 总和 / 两轮calls总数。
- `p50_ms,p95_ms,p99_ms,max_ms` 来自两轮全部384条原 measured latency。
- `round_calls_per_second`、`round_controller_cpu_ms_per_call` 保留轮间差异。
- `change_percent.calls_per_second`、`change_percent.controller_cpu_ms_per_call` 等 =100×(B/A−1)；A分母0时为null。

这里的 B/A 比较用于观察开启记录的影响和选择下一步排查方向，不是某个新优化版本相对 accepted R24 的收益，也不建立两轮样本的统计显著性。

controller CPU 的原分子是：
`N.rounds[r].cells[0].raw_timing.controller_before/after` 中同 PID/birth_ticks 的 `utime_ticks+stime_ticks` 差 / `clock_ticks_per_second`。
对应现成值为 `cells[0].controller_cpu_seconds`。CPU计数读取区间包住测量wall区间，存在tick粒度和端点差异。

### RSS

先列四轮 first-controller 的实际 `controller_rss_kib`；restart另列，避免混为纯C1 measured内存。需要一个明确汇总数时，可派生：

- first生命周期的 OFF峰值=max(r0,r3)，ON峰值=max(r1,r2)。
- ΔKiB=ON−OFF；百分比在OFF>0时才计算。它是“first生命周期 sampled峰值差”，不伪称新增验收门槛或原JSON中已有的聚合字段。
- 如另报包含restart的全生命周期最坏值，明确是四个controller/arm的max，勿与first-only指标混用。

同时读取该resources对象的 `metric_samples.controller_rss_kib`、`errors/error_counts`、`sampler_error`。没有该metric样本时0表示不可用，不表示0 KiB。FD采样错误不能自动抹掉独立可读RSS。

`cells[0].sampled_resources_before/after.peaks` 是累计峰值，**两峰相减不是measured RSS峰值或RSS增长量**。若必须对齐measured区间，只能另外从已保留的 `first/resource-samples.jsonl` 中选落在原cell区间的controller样本，标为派生的区间采样峰值；不新增采样。100 ms采样会漏峰，tree RSS是非原子求和且可能重复计算共享页。

## 5. wall 不可相加；未归因 CPU 的命名

`phase_wall_nonadditive` 的所有 `sum_ns` 都不能直接相加为请求总耗时：外层 `request` 包住内部phase，同步scope与async wait可以嵌套，不同任务/线程的wall可以重叠。inclusive CPU同样不能跨父子相加；做CPU预算使用exclusive。

三段派生queue wall的端点精确为：

| 指标 | 端点 |
|---|---|
| channel_wall_ns | queue_submitted → queue_received |
| pending_until_initial_global_grant_wall_ns | queue_received → initial_capacity_granted |
| dispatch_schedule_wall_ns | initial_capacity_granted → owner_execute |

三段都存在时，它们只覆盖 submitted→owner_execute 这一连续链；不能再与覆盖它们的queue/admission/request外层wall叠加，也不代表请求全部时间。它们不是CPU，不能把等待长直接归因为本地计算或纯网络时间。

可对每个ON measured cell派生：
`R_r = controller_cpu_seconds * 1e9 − Σ(S_i for i in M_r)`。

标签用 **“未归因/区间与时钟残差”**，不要标成“SSH CPU”“远端CPU”“锁等待CPU”或“可优化浪费”。它混合未埋点/后台controller工作、未计入scope的记录成本、process-tick与thread-CPU计量差异、端点差异；已记录parent exclusive本身也可能含诊断bookkeeping。R<0时原样保留并注明度量不闭合，不截成0；C=0时占比不可用。

parser故意返回以下null：
`trace_summary.controller_total_cpu_ns`、`ssh_child_cpu_ns`、`remote_helper_cpu_ns`、`network_only_wall_ns`。
OFF也没有请求级CPU trace。子进程采样CPU可读原resource，但它是非完整生命周期累计/不同步端点的诊断信息，既不是controller CPU分子，也不能用来填上述null。Python harness采样/transport capture的CPU不包含在controller计数内。

## 6. 结果到达后的最短阅读顺序

1. 沿既有原协议读P/holder最终状态、I.verified、A.analysis_complete/errors以及原清理结果；失败不进入成功成本解释。
2. 读I.cases[0]，先看ON/OFF throughput、CPU/call和两轮各自值，标记记录模式的观测影响。
3. 仅筛t=2、4的192条measured请求，按host×operation看S_i绝对值与队列三段；保留两轮，不混入warmup/restart。
4. 需要phase定位时才做原raw event的measured exclusive派生。优先记录CPU绝对值大的phase；wall大的phase只说明相应区间长，先结合queue和native latency判断。
5. 同时报告同cell的CPU残差及RSS作用域；没有埋点覆盖的数据标未知，不推断为0。所得方向用于下一轮独立候选，不修改本次阈值或补跑测量。

## 冻结源码依据

- adapter03：Git `1b55bf0634ec60855f7965223742ea10abf716d9`，31,131 B，SHA256 `b49b95b00f67b33b05b726527ee5f63766fe568f7fed6d372f32417d3f811189`。
- summarize_trace.py：Git `064cd62dd7f60ee11d538b4b21f4674283591572`，15,057 B，SHA256 `f6e65c2e206d4aa90143a17893e5e57c158bca9f8eec5f74897b19c3596e32c5`。
- 原native analyzer：Git `f00a7f7f81621912318b7d585e1ffc02d6e96c3f`。
- 原benchmark：Git `19c429f682afdf24112f579e7717155cc005dd53`。
- 原resource sampler：Git `5c12e37a14f59e8ccc431565868408df45738663`。
- 原warmup wrapper：Git `8db361d227f6240ae548a803082d17f846fa6563`。
- outer05：Git `590e6740975acc686d351b5b07863256f29cd10e`。

这些源码均已只读取回并核SHA/Git身份；本指南没有运行它们。
