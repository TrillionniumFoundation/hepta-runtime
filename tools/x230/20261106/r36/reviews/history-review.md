# R36 历史核验：有限停止边界

**现有证据支持停止本轮并保留 R24；没有发现已由现成材料证明为低风险、高收益的遗漏开关。这个结论不证明所有优化已穷尽。** 本核验仅读取本地仓库与原始报告，没有构建、负载、远端调用或源码改动。R36 的必选 normal lifecycle 已失败；完整资格通过不能改变拒绝决定。

## 精确来源

历史文件固定在 Git 提交 `86155fbf3b89e5a77e2a4aadebd2128c663fe50b`。八份引用的工作树正文均逐字节与该提交的 Git blob 比较一致；完整路径、blob、SHA-256、大小和相关主题见同目录 `history-review.json`。本核验不把未部署的候选当作生产服务现状；R24 是已接受的性能基线。

| 来源 | 本次核验用途 |
| --- | --- |
| `Cargo.toml` | 当前 release／dev 配置 |
| `docs/X230_A17_SOURCE_20261023.md` | A17 已保存源码与构建的历史背景 |
| `docs/X230_OPTIMIZATION_R5_R7_20261030.md` | 早期正式 release 已记录 O3／LTO／单 codegen unit |
| `docs/X230_OPTIMIZATION_20261103_R13.md` | 实际 qualification 与 release 配置口径 |
| `docs/X230_OPTIMIZATION_20261103_R15.md` | allocator 诊断、正式 arena1 比较及 prep4／arena2 边界 |
| `docs/X230_OPTIMIZATION_20261104_R16_R18.md` | worker／并发 ABBA、hash buffer 实验和下一层边界 |
| `docs/X230_OPTIMIZATION_20261104_R19.md` | 现有 hash 实现与硬件指令集限制 |
| `tools/x230/20261028/qualify.py` | 构建环境过滤、固定 worker 与 build jobs 设置 |

## 编译配置不是新的免费收益

当前 release 已设置 `opt-level=3`、`lto=true`、`codegen-units=1`、`panic="abort"`、`strip=true`；R5–R7 与 R16–R18 的实际实验报告也记录同一配置。重新启用这些选项不能算新增优化。Git 提交 `29b175b9180cb7f73ad988a470375292d4c023e4` 的 Cargo diff 将 opt-level 从 `"s"` 改为 3，同时加入 redb；它不能单独证明 O3 的隔离 ABBA 收益。[固定 Cargo](https://github.com/TrillionniumFoundation/hepta-runtime/blob/86155fbf3b89e5a77e2a4aadebd2128c663fe50b/Cargo.toml) · [历史变更](https://github.com/TrillionniumFoundation/hepta-runtime/commit/29b175b9180cb7f73ad988a470375292d4c023e4)

当前 qualifier 明确移除 RUSTFLAGS、CARGO_ENCODED_RUSTFLAGS、RUSTDOCFLAGS 及 Rust wrapper 变量，并固定 Tokio workers=2、jobs 只允许 1／2。它本身没有清除所有 `CARGO_PROFILE_*` 变量，因此不能只凭该 helper 声称一切 profile 覆盖都被排除；本轮实际输入与构建身份另由原 qualification 绑定。[原 qualifier](https://github.com/TrillionniumFoundation/hepta-runtime/blob/86155fbf3b89e5a77e2a4aadebd2128c663fe50b/tools/x230/20261028/qualify.py)

在当前 `docs/`、`tools/` 的 `.py/.md/.toml/.sh` 及 Cargo.toml 中检查 target-cpu、profile-generate／profile-use、llvm-bolt、PGO／BOLT 和相应 release profile 覆盖变量，未找到已报告的编译矩阵或收益。搜索命令及范围保留于 JSON；没有穷举全部 Git 历史、私有实验或所有编译器技术。R16–R18 本身把面向该 CPU 的编译变体列为尚未验证、需考虑可移植性的下一层方向，不能改写为“已测无效”。

## Worker、并发与 allocator 已有明确取舍

R16–R18 用同一合格 R14 release binary 分别做 workers=2 对 1、2 对 4 的两组独立 ABBA。每组 C1／C8／C16、每 cell 96 measured＋24 warmup，合计 1,512 calls、0 failed；不同 campaign 的性能样本不池化。[原 worker／并发报告](https://github.com/TrillionniumFoundation/hepta-runtime/blob/86155fbf3b89e5a77e2a4aadebd2128c663fe50b/docs/X230_OPTIMIZATION_20261104_R16_R18.md)

| 已测方向 | 结果 | 对下一步的限制 |
| --- | --- | --- |
| workers=1，C16 | 吞吐 −2.537%、CPU/call +2.364%、p99 +7.891%；Controller HWM 均值减少 1,432 KiB，但 SSH 采样 RSS +7.528% | 减少 worker 不同时改善吞吐和整个进程树资源 |
| workers=4，C8 | 吞吐 −2.160%、CPU/call +1.300%、Controller HWM +11.550% | 更多 worker 不是通用升级 |
| workers=4，C16 | p99 −11.337%；吞吐相邻配对 −0.930%／+4.999%，CPU +2.003%／−3.226% | 特定尾延迟目标可有不同取舍，没有稳定通用吞吐收益 |
| workers=2，C8 → C16 | 两组 campaign 吞吐 +0.93%／−3.11%，p95 约 +92%／+103% | 固定 warm observation 分布下增加并发主要增加等待；不代表所有负载的硬上限 |

R15 allocator 诊断顺序为 default／2／2／default 与 1／4／4／1，包含 warmup，后台归档 I/O 可能重叠，因此原报告没有给诊断吞吐结论。正式同二进制 ABBA 比较 clean default 与 arena1。大 receipt（4,194,272 B）的 workers=1／2 HWM 从 106,338／102,650 降至 29,070／30,720 KiB，但 mixed rate 为 +0.48%／−3.75%、CPU/RPC −1.88%／+2.60%、host_list p95 +35.84%／+22.23%；小 receipt workers=1 的 CPU/RPC +6.49%、rate −6.03%。这些是实际取舍，不能只引用内存改善。[原 R15 报告](https://github.com/TrillionniumFoundation/hepta-runtime/blob/86155fbf3b89e5a77e2a4aadebd2128c663fe50b/docs/X230_OPTIMIZATION_20261103_R15.md)

arena2／4 的限定诊断不等于正式全矩阵，prep4 也未在 R15 正式测量。SMT 或成功取消的 I/O／fsync overlap 仍可能带来收益，但会引入更多 buffer 与 allocator／scheduler 竞争；native status/read 不取得 cancel preparation semaphore，不能把 prep4 当作直接修复 native C8 的办法。专用线程还需额外证明交接、队列取消、部分初始化及 shutdown／reap 行为。历史数据属于当时基线和负载，不证明 R24 在任何工作负载下都是最优配置。

## 现有 hash、语义边界与 R36

R16 的 16／64／256 KiB hash buffer 比较未建立放大 buffer 的稳定收益；R19 已使用 ring SHA256，并记录该 X230 没有 SHA-NI／AVX2。不能重新提议“换成 ring”作为未尝试增益，也不能通过省略完整 pin 校验、改持久化顺序或弱化取消语义获得表面加速。[原 R19 停止边界](https://github.com/TrillionniumFoundation/hepta-runtime/blob/86155fbf3b89e5a77e2a4aadebd2128c663fe50b/docs/X230_OPTIMIZATION_20261104_R19.md)

R36 选择普通／保留请求成功末端的所有权移交，静态否决验证前消耗整个 hot cache 的方案。完整资格通过，但 normal lifecycle 的 all_operations 吞吐及 launch 吞吐、p95、CPU 四个必选门限失败，候选拒绝。正常 observation／lifecycle 主要沿用原已有所有权移交的 batch 路径；本轮没有记录两个改动路径的命中次数，不能把原差值解释为该复制移除的因果效果。相关 async 路径补充封存后未执行，saturation 也未执行。

既有 `--runtime-audit-group-commit` 已启用；下一层应理解为进一步的 durability／批处理重设计、owner 状态分片或专用等待执行机制。这些方向需要新的 ACK／持久化、锁顺序和取消／reap 证明，以及独立测量；它们不是本轮已完成收益。保留 R24、停止本轮建立在实际拒绝结果和已有取舍之上，**不声称全局最优、Pareto 最优或所有可行优化已经穷尽**。
