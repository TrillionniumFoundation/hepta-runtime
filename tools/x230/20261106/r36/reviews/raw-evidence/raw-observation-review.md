# R36 Observation 原始证据复算

**原 observation analysis 全对象相等，重新序列化后的 62,873 字节也与原件逐字节相等。** SHA-256 为 `b2695e1c9992b0b0a9b547ea2d64e4da6fa83e7b5616ebb294215849b470bda0`。本次支持原 observation 非退化通过的证据，不改变 R36 因必选 lifecycle 失败而被拒绝的决定。

## 核验范围

| 项目 | 原件复算结果 |
| --- | ---: |
| 原始 transport frames／RPC envelopes | 2,672／2,672，全部逐条核验 |
| Tool calls | 2,664 = 2,304 measured + 288 warmup + 72 preflight/restart |
| Failed tool calls | 0 |
| Controller generations | 8 |
| Resource trace records | 1,565，全部重算 |
| 原 CPU ticks 与单调时钟 cells | 24；另核对每个 cell 绑定所属 startup PID／birth-ticks |
| 六主机 frozen job record 副本 | 四轮共 24 份，SHA 全部与原 report 指纹相等 |

冻结的本地 analyzer 复算每个请求绑定、完整 wire frame、DTO、status 终态和读回 stdout／stderr 的字节 SHA、游标及长度，并从原单调时钟端点重算逐条 latency；从 raw `/proc/stat` 字符串核对 CPU ticks，从 resource traces 重算峰值、分类、代际与原始 missing/error 记录。Resource trace 条数与有效 Controller RSS 样本数不是同一个指标；原 summary 的有效 Controller RSS 样本为 1,564，保留的 trace 共 1,565 条。

原始 A/B 指标全部与既有 analysis 相等：C1/C8/C16 吞吐变化分别 −0.8825%／−2.2104%／+0.4372%；CPU/call −0.4129%／−0.9358%／−1.5345%；Controller 采样 RSS 峰值 19,032→18,864 KiB。有限 ABBA 与配对方向不稳仍不证明稳定加速。

## 归档及执行边界

压缩归档为 3,961,240 字节，SHA-256 `30ff7e2dae12aa00a0048c9808610a76b17b4a37daa9de32dfab1fea06f2c9c9`。在访问白名单前，独立检查全部 9,448 个成员为规范路径的普通文件，重算 9,447 个 payload 的大小／SHA，核对 manifest、9,478 条 inventory entries、31 项 omission 及目录祖先对应。

实际只向可信审计器提供 59 个明确的 OBS 数据成员，均从内存读取。执行的是本地冻结 `analyze_native_observation.py`、`audit_native_evidence.py`、`allocator_environment_audit.py`；三个代码正文及未执行的 allocator helper 均与原归档的固定来源 SHA 相等。没有导入或执行归档脚本，没有按 payload 的绝对路径读取本机文件，也没有运行远端、workload 或 fixtures。

最初尝试创建新的白名单解包目录时遇 ENOSPC，尚未创建目录或写出数据文件。随后仅改用内存 Path 适配器，冻结的计算及审计函数保持原样。完整复算结果已一次完成，空间恢复后直接保存内存结果，没有重新运行算术或实验。

## 尚未由本次证明的范围

六个原作业的四轮本地副本与 report 指纹一致，wire 中的结果也与这些指纹一致；没有读取归档外的原作业路径或再次查询远端。Private profile／runtime／SSH 正文和 ELF 为明确 omission；本次没有新做 ELF 哈希或实时环境检查。Topology 绑定六个不同的已报告 machine groups，没有新做物理主机身份探测。

本次只复算 native observation。容量边界与恢复 canary 保留其原 reported pass／hash 绑定，没有追加运行它们的独立审计器。非原子的进程树采样仍可能缺失短命进程或重复计共享页，不能将采样总量解释为精确集群 CPU／内存。饱和取消和 async 补充仍未执行。

完整身份、白名单、CPU 代际绑定、原缺失记录、重算 metrics 与限制见 [raw-observation-review.json](raw-observation-review.json)；可复现的本地只读检查脚本为 [review_raw_observation.py](review_raw_observation.py)。旧汇总 review 的范围声明按其生成时状态保留，本文件提供新增的原始证据复算结果。
