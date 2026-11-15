# D2 recovery02：实际 measured CPU 成本与 R36 范围

本文件是对已返回 DERIVED 投影的本地算术解释，不是新的审计或验收流程。未执行 host、原 parser、原 auditor、workload 或 R36。

**结论：whole validation 为 20.968415 ms/请求，占 controller CPU 62.660478%；R36 两处目标所在的父 exclusive 总余量只有 1.235220 ms/请求、3.691242% controller CPU。R36 仅涉及该余量的一部分，不能将整段读取或验证预算当作可回收收益。**

## 精确来源

- 原 adapter report：8,827,749 B，SHA256 `d882031e45096ddddee57dd83b580b5dc3ff15ebe2481b9c9a1dd2d109d44807`。
- 返回投影：Git `e633612cc65afcd24907382676776938dc10a985`，296,868 B，SHA256 `d1243423b5fe119653b3185627d8a6a638c6a0f2c946880a7ded05db178ed479`。本次本地原 bytes 和已发布 Git body 均独立重算一致。
- 原投影脚本：Git `2ce9e95f8b108faeb3db3b02f70217b33b683943`，其完整源读取/SHA校验由 root 原次执行；本计算不声称重新读取全部8.8MB源或 raw traces。
- 本地计算脚本：Git `4533c46c978fe7c393952119763520d2b30092c8`，9277 B，SHA256 `c5b1a8b95d0e10b722a9ac5cb03582c406bc280d82ad7e81eac827775c56832a`。
- 精确计算数据：Git `5a256efe675ed3fea408b18712043b1965fb36ab`，23508 B，SHA256 `b8b6d6257e8347544fb46581908072a90608ece2543b9947a07f60eaf62b95e7`。保留每项整数 ns 总量、请求分母及12位小数展示值。
- 口径：冻结文档 Git `f14fad02c9f32637f057e7df7c36526f8155110f`。

## 两轮 ON 与合并

只选 `$.adapter.traces[2]` 和 `[4]` 的 `category_phase_summaries.measured`，分别192请求；384个 measured ON 不含 preflight、warmup 或 restart。原 adapter 的468个唯一 ON 联接与8条 trace均保留在计算数据中。

| 范围 | 请求数 | Controller CPU ms/请求 | Whole validation ms/请求 | Whole / controller | 父 exclusive ms/请求 | 父余量 / controller | Signed residual ms/请求 |
|---|---:|---:|---:|---:|---:|---:|---:|
| ON round 1 | 192 | 33.645833 | 21.127756 | 62.794569% | 1.247740 | 3.708454% | +9.170905 |
| ON round 2 | 192 | 33.281250 | 20.809074 | 62.524918% | 1.222700 | 3.673841% | +9.191671 |
| 合并 | 384 | 33.463542 | 20.968415 | 62.660478% | 1.235220 | 3.691242% | +9.181288 |

Controller 分母直接来自原 measured counter：round1为646 ticks，round2为639 ticks，均100Hz，总12,850,000,000ns。CPU计数器每tick为10ms；表中小数是算术精度，不意味着原计数器具有相应测量分辨率。合并先相加原整数分子/分母，不直接平均百分比。

## 七个 child：exclusive 分解

| 阶段 | ms/请求 | 占 controller CPU | CPU events/请求 |
|---|---:|---:|---:|
| 初始 checked_file (`file_checked`) | 3.982885 | 11.902161% | 72 |
| 完整 reference 读取/比较循环 (`file_read_reference`) | 6.416265 | 19.173898% | 36 |
| 完整 read/hash 循环 (`file_read_hash`) | 0.674518 | 2.015681% | 36 |
| 最终 verify_read (`file_final_check`) | 3.949858 | 11.803467% | 72 |
| 额外身份复核 (`file_identity`) | 1.743549 | 5.210295% | 36 |
| shell resolution (`shell_resolution`) | 2.228946 | 6.660820% | 18 |
| profile policy (`profile_policy`) | 0.737173 | 2.202914% | 18 |
| 七个 child 合计 | 19.733195 | 58.969236% | — |

Whole validation 使用 worker+owner 的 **inclusive**：worker 9.389947 ms，加 owner 11.578468 ms。两父 exclusive 分别 0.559072 和 0.676148 ms。

精确整数恒等式：

```text
8,051,871,370 ns whole inclusive
= 7,577,546,820 ns seven child exclusive
+   474,324,550 ns two parent exclusive
```

两轮分别与合并都满足该恒等式，差为0；没有父子重复相加。全 recorded sync exclusive 为 24.282254 ms/请求（72.563311% controller），其中验证之外的已记录同步工作为 3.313839 ms/请求。

Signed controller-minus-recorded residual 为 +9.181288 ms/请求（27.436689%）。保留原正负算式，没有截零，也没有归因给 ssh child、远端 helper 或网络；它包含未记录/后台/诊断工作以及计数窗口差异。

## R36：只能给直接成本预算，不能给收益承诺

已核冻结 profile Git `a68cdc86cd3eed479d21028cdb4a13157376b4f7` 和补丁 `273f9f72dd2e8da9d26cad55403cc09694bc96c3`。R36只做同一同步 sweep 内惰性16KiB scratch复用，以及 reference存在时避免构造未使用的SHA Context。两者位于 worker/owner 父 exclusive，而初始fresh open、完整read/compare/hash、最终reopen、identity、shell与policy保持。

把**整个**父exclusive都假设消失且其它CPU完全不变，才得到每请求1.235220ms、controller3.691242%的乐观直接预算；纯CPU服务率算式为 `1/(1-0.03691241634241)=1.038327164599`。这不是R36的实测收益，也不是生产吞吐预测或无条件物理上限。该余量仍含不可归给R36的原检查、reader/结果处理、析构及诊断记账；编译器也可能已消除一部分初始化，候选仍可能无收益或回退。

`file_read_reference` 的6.416265ms包含完整读取、比较和原取消检查，R36不删除它。D1的约14.01373ms与本次20.968415ms来自不同细分诊断；不能把差值当成生产回退。ON/OFF只用于诊断开销校准，本投影不足以重算完整OFF/ON吞吐或RSS，因此此处没有这些额外数值。

没有相加不同阶段的median/p95或重叠wall spans。采纳仍由原完整资格、并发/生命周期和性能规则决定。
