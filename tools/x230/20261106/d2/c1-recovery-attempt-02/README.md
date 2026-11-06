# D2 C1 recovery02：诊断完成与证据收尾

Recovery02 的原 C1 诊断执行已成功闭合，936 次 native 调用均成功，8 个 controller 与持有 agent 的回收记录完整。本轮只提供验证成本定位证据；**没有因此采纳任何 production candidate，ON/OFF 也不代表生产性能增益。**

## 原始结果与尝试历史

| 项目 | 原次实际结果 |
|---|---|
| Native 调用 | 936：768 measured、96 warmup、72 preflight/restart；失败 0 |
| 独立 native 审计 | `verified=true` |
| Controller / trace | 8 个 controller 完整关闭；8 份原始 trace 保留 |
| Compiler monitor | 254 个样本，`passed=true` |
| 源码 | `sources_unchanged=true` |
| Mac holder | 252.895 秒；持有 agent 与私有 socket/目录清理闭合 |

[首次 attempt01](../c1-first-attempt-01/) 的失败及完整证据继续保留。它因历史 profile 根目录缺失而在 workload 前退出，原 parent 的 `stages=[]`；该失败没有被改写成成功。

Recovery02 使用新的 C1 专属 02 namespace 和已核身份的 D1 私有派生 seed。拓扑只更换 seed SHA 字段，六份 frozen job 原字节保持；原 Q、exact CI、ordinary、postflight、源码与 feature ELF 继续使用已闭合的 01 原件。恢复来源与条件性内容等价证明见 [准备包](../c1-recovery-preparation-02/) 和 [独立审查](../c1-recovery-independent-review-02/)。私有 profile、ssh_config 与 known_hosts 正文不在本次发布中。

## 完整归档：原验证与整件字节校验均完成

原 collector 已生成 `c1-evidence-02.tar.gz`：

- 长度：7,340,932 B。
- SHA256：`b67ff03f88aecd289a58c3774e9335bd55620fe1d35f41feb8feb09ccf299464`。
- Manifest SHA256：`56177c4611c8b8d872eea81bdd9d35f4fab2c599647dab917e0ea81af5141a8c`。

原 zero-extraction verifier 仅执行一次，原作业 `1a1b1b79ce0-fc05-7a74` 已 `succeeded`、exit 0；完整 durable 输出为 628 B stdout / 0 B stderr。原结果为 `verified=true`、`files_extracted=0`、1,645 files、79,575,406 selected B、8 raw traces、`receipt_binding_errors=[]`、`outcome=diagnostic_passed`，调用计数仍为 936/768/96/72/0。

完整归档已完成 immutable 回传与整件 SHA256 校验，并实际创建 Git blob `45e901116f8d1bbc43a83cce503aa895fe812b36`。回传使用已校验的原 x230 文件及一份经完整 SHA256 验证的 Mac 副本；两段超时读取单独恢复，成功字节继续保留。原 verifier 仍只执行一次。

[完整归档](archive/c1-evidence-02.tar.gz)、[原 manifest](archive/c1-evidence-02.manifest.json)、[compact](archive/c1-evidence-02.compact.json) 与原验证执行回执均已发布到 `archive/`。完整归档保存原 report、raw trace、native 请求证据、原审计与监测/回收日志；派生投影与算术结果另行保留。

## 成本投影与可重复算术

原 adapter report 为 8,827,749 B，SHA256 `d882031e45096ddddee57dd83b580b5dc3ff15ebe2481b9c9a1dd2d109d44807`。原次只读 projector 完整核对该身份后，选取已有 aggregate 字段，产生明确标注 DERIVED 的投影：

- [cost-projection.json](../c1-cost-projection-02/cost-projection.json)：296,868 B，SHA256 `d1243423b5fe119653b3185627d8a6a638c6a0f2c946880a7ded05db178ed479`，Git `e633612cc65afcd24907382676776938dc10a985`。
- [投影脚本](../c1-cost-projection-02/project_c1_cost_02.py) 和 [静态独审](../c1-cost-projection-02/independent-review-01.json)。
- [精确计算数据](../c1-cost-analysis-02/cost-calculation.json)、[计算源码](../c1-cost-analysis-02/calculate_costs.py) 与 [完整成本说明](../c1-cost-analysis-02/README.md)。

计算只读取返回投影，保留原整数 ns 总量与请求分母，没有运行原 parser、auditor、workload 或 R36。两个 ON measured 轮次各 192 请求，合并 384 请求；比例由原分子/分母分别求和后计算。

| 合并 384 个 measured ON 请求 | ms/请求 | 占 controller CPU |
|---|---:|---:|
| Controller CPU | 33.463542 | 100% |
| Whole validation：worker + owner inclusive | 20.968415 | 62.660478% |
| 七个 child exclusive 合计 | 19.733195 | 58.969236% |
| 两父 exclusive 余量 | 1.235220 | 3.691242% |
| 全 recorded sync exclusive | 24.282254 | 72.563311% |
| Signed controller-minus-recorded residual | +9.181288 | +27.436689% |

Whole validation 精确等于七个 child exclusive 加两父 exclusive；不能再次把 child 加到 inclusive 父总量。Signed residual 保留正负号，不归因给网络、ssh child 或远端 CPU，也不相加重叠 wall spans 或不同阶段的 p95。

## 对 R36 的约束

R36 的惰性 16KiB scratch 复用及避免无用 SHA Context 只涉及父 exclusive 余量的一部分。把整个父余量都消掉才是每请求 1.235220 ms、controller CPU 3.691242% 的乐观直接预算；该假设不是 R36 实测收益、生产吞吐预测或无条件物理上限。

完整 reference 读取/比较循环的 6.416265 ms/请求、fresh open、最终 reopen、identity、shell 与 policy 成本均不能直接计入 R36 可回收预算。D1 与 D2 使用不同细分诊断，成本差不能据此解释为生产回退。R36 是否可采用仍由其原完整资格与性能门槛决定。
