# R36 Normal lifecycle 独立复核：拒绝采纳

**R36 没有通过原 mandatory normal-lifecycle 门限，维持拒绝结果。** 所有数值与原 gates.json 一致；没有改门限、丢弃样本、追加重测或用通过的子项抵消失败项。

| 必选分组 | RPC/s A → B | 吞吐 B/A／变化 | p95 A → B，ms | p95 B/A／变化 | Controller CPU B／原上限 | 结果 |
|---|---:|---:|---:|---:|---:|---|
| all_operations | 8.101553 → 7.665013 | 0.946116439 / -5.3884% | 769.411710 → 809.717277 | 1.052384915 / +5.2385% | 0.37s / 0.45s | 失败 |
| launch | 7.300412 → 6.479951 | 0.887614492 / -11.2386% | 827.582680 → 1019.395308 | 1.231774580 / +23.1775% | 0.12s / 0.11s | 失败 |
| concurrent_cancel | 7.277395 → 7.259050 | 0.997479132 / -0.2521% | 882.146409 → 841.164474 | 0.953542933 / -4.6457% | 0.07s / 0.08s | 通过 |

原门限：throughput B/A ≥0.95；p95 B/A ≤1.10；Controller CPU为 A 总量加每个 B phase/round 一个 raw clock tick，并保留原代码1e−12比较容差。CPU门限不是10%相对变化。

明确失败四项：all_operations吞吐；launch吞吐、p95和Controller CPU。Launch的100 Hz计数对应A=4+5=9 ticks、B=7+5=12 ticks；两轮容差2 ticks后上限11 ticks，仍超1 tick（0.01秒），不是浮点取整误判。

RSS通过：A 17,436 KiB，B 17,696 KiB，增加260 KiB（+1.4912%）；上限min(A+512,A×1.05)=17,948 KiB，余量252 KiB。该结果为Controller采样峰值。Concurrent cancellation三项通过，但不能抵消其他mandatory项失败。

## 复算内容和拒绝链

本次1138项一致性检查通过；另一个只读reviewer独立完成519项检查。从gates内20个C6 cell、120条latency值重算全部分组：每臂all_operations为60次调用／10个RPC时间窗；每个独立phase为12次／2窗。吞吐使用calls/sum(RPC spans)；p95为nearest rank，60条取第57条，12条取第12条。11阶段×4轮的顺序、44个原phase文件身份、phase汇总、generation对应、完整计数及四份原audit绑定均一致。

四轮正常canary及原audit各自返回0，summary返回0；normal-lifecycle-gates返回1，inner report passed=false；outer normal-lifecycle-abba返回1，外层passed=false、adoption_passed=false。输入未变、编译监测有效，失败不是timeout。summary verified=true表示证据完整，不能解释为性能采纳通过。

**边界：原四轮report、44个phase原件、wire、/proc原始字符串及resource trace尚未下载，本次没有宣称原始证据重审。** RPC span与CPU来自原analyzer导出的cell，已与phase summary交叉验证；分位数则确实从cell内120个latency数值独立重算。以后归档原件到位可验证其来源链。

外层报告明确保留independent_controller_cleanup=unknown；owned stage process/group absent已报告，不能据此声称所有独立Controller session均已清除。原逐轮审计是否充分证明独立Controller闭合，须读取归档中的原件。

## 处理结论

维持R36拒绝采纳，保留失败原件。主线程已决定停止后续async与saturation实验；不重测来寻求通过。这是一次有限ABBA在预设门限下的决定，不宣称统计显著性，也不推测回归必然由某个代码机制导致。吞吐指标为native lifecycle RPC，不是job compute吞吐或最大并发容量。

完整数据、失败项、文件SHA和范围声明见同目录`lifecycle-review.json`，本地复算程序为`review_lifecycle.py`。

## 复核原件身份

| 文件 | 字节 | SHA256 |
|---|---:|---|
| lifecycle-gates.json | 17202 | `243dd43cda85f1ad7700c9eba7f3cf4583edc6641cf4259447cbca71c648924e` |
| lifecycle-summary.json | 60616 | `6dd4723959fde86bcc41f2d466d74a800a32a7658f7f3f30d35a76737e9d5fca` |
| lifecycle-report.json | 32373 | `1ee73f9556b2ce0e139394e5add300fcf49c2ad985ed00eb16064e9f6842cebb` |
| lifecycle-round-index.json | 15137 | `bff451b8bff33fbaff9198f2e8525bd845b1a593985d2b40c6cc26ae2caba71f` |
| lifecycle-parent.json | 79577 | `f5da48f7569240789a9c30d9661dd74ea797297fa6e12e715bc420316b00f020` |

生成时间：2026-11-06T10:47:16.737044+00:00。只写新review文件；未改冻结控制、源代码或远端状态。
