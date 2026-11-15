# R36 原始证据独立复核

**原始证据复核通过，R36维持拒绝采纳，保留已接受的R24性能基线。** 本次从实际下载归档重新核验原wire、RPC时钟、CPU counters、资源trace和生命周期结果；四项原必选失败完全重现。没有执行任何新负载，也没有修改冻结门限或源代码。

## 原件与复核范围

归档为3,961,240字节，SHA256 `30ff7e2dae12aa00a0048c9808610a76b17b4a37daa9de32dfab1fea06f2c9c9`。独立v2 verifier通过：9,448个规范regular members＝9,447个payload＋manifest，31项明确metadata omission，44份holder原件绑定；原capture01失败保留。有界raw/decoded secret扫描未发现其定义模式。

所有计算只执行本地已冻结、hash绑定的可信auditor。归档内脚本仅作为字节验证，不执行；report中的X230绝对路径只作身份文本，不用于访问外部filesystem。

| 复核部分 | 实际原始数据 | 结果 |
|---|---|---|
| Native observation | 2,672 frames/RPC envelopes；2,664 tool calls，其中2,304 measured、288 warmup、72 preflight/restart；8代Controller、1,565 resource records、24 raw CPU cells及24份冻结job副本 | 原62,873字节native analysis逐字节重现，SHA `b2695e1c9992b0b0a9b547ea2d64e4da6fa83e7b5616ebb294215849b470bda0`；0 failed calls |
| Normal lifecycle | 4轮、12代Controller；360 native RPC、372 frames、288 SSH streams、416 resource records、24份retained job records；44份phase原件，其中40个Controller CPU bracket、20个operation cells／120条latency | 四份原独立audit对象与phase summary完全重现；原gate结果完全重现，仍失败 |
| Compiler monitor | Observation与lifecycle两份完整ledger | 独立重算均通过，分别300和148个sample；原validation对象完全一致 |

详见[OBS原始数据复核](raw-observation-review.json)、[lifecycle原始数据复核](raw-lifecycle-review.json)和[12代Controller闭合补证](raw-controller-closure-review.json)。

## 性能结论保持原样

Observation三个档的原非退化门限均通过，但没有建立稳定加速：

| 并发 | 吞吐变化 | p95变化 | Controller CPU/call变化 |
|---|---:|---:|---:|
| C1 | −0.8825% | +0.8056% | −0.4129% |
| C8 | −2.2104% | +6.2838% | −0.9358% |
| C16 | +0.4372% | −1.3748% | −1.5345% |

Observation Controller采样RSS峰值19,032→18,864 KiB，下降168 KiB；1,565条resource records中1,564个有效Controller RSS样本支持该统计。资源缺失／退出竞争／权限记录仍完整保留，不能表述为所有采样操作无错误。

Normal lifecycle明确失败四项：

| 必选项 | 实际值 | 原门限 |
|---|---:|---:|
| all_operations吞吐 B/A | **0.946116438946** | ≥0.95 |
| launch吞吐 B/A | **0.887614491524** | ≥0.95 |
| launch p95 B/A | **1.231774579913** | ≤1.10 |
| launch Controller CPU | **0.12 s** | ≤0.11 s |

Launch的原100 Hz counter对应A=9 ticks、B=12 ticks；两轮声明容差2 ticks后上限11 ticks，仍超1 tick。Concurrent-cancel三项和lifecycle RSS通过，不能抵消上述必选失败。Lifecycle RSS为17,436→17,696 KiB，增加260 KiB，上限17,948 KiB。

重算gates时仅把`round_index.path`与`gate_policy.path`两处本地审阅路径归一回原路径字符串；两份文件的bytes/SHA保持不变，其余完整对象完全一致。具体原／本地路径记录在JSON中。RPC throughput不是job compute吞吐，也不是最大并发容量测量。

## 12代Controller的独立闭合补证

四轮中，4代首次Controller为`exit_code=-9 / shutdown_method=already_exited`，8代为`exit_code=0 / shutdown_method=stdin_eof`。全部12代的reader/sampler error为null、EOF为true、unmatched为0、observed descendant survivors为空；36份transport/index/resource正文及12份stderr与最终回执hash、startup PID/birth和原始stat身份闭合。

结合固定源码，可单独确认这些已记录Controller经历wait/close，本地transport reader和resource writer经历join、flush、fsync、close后才生成最终hash回执。**原外层`independent_controller_cleanup="unknown; stage-group absence is insufficient and no workload is retried"`原样保留。** 本补证只覆盖历史12代Controller、本地writer和已观察后代，不等于一次新的live process scan，也不声称所有可能的SSH或远端进程都被观察为不存在。

## 明确边界

原observation boundary和单候选recovery canary保留原通过结果及hash绑定，本补审没有扩展重跑其independent auditors。资格／CI证据也没有重新执行。私有profile、runtime／SSH／agent配置和ELF正文按原政策省略，未读取或重建。

本地OBS数据材料化曾在建目录前遇ENOSPC；随后只用内存白名单adapter完成同一可信analyzer，未生成负载重试。生命周期audit完成后，仅删除了自己创建的805个可从归档重建的临时regular数据文件，原归档、冻结工具和审阅成果未改。Async read补充和saturation在normal-lifecycle失败后均未执行。

完整文件身份和分项结论见[汇总JSON](raw-evidence-review.json)。复核程序：[OBS](review_raw_observation.py)、[lifecycle](review_raw_lifecycle.py)、[Controller闭合](review_raw_controller_closure.py)。
