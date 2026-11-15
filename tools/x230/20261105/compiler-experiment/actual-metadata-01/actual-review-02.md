# X230 compiler metadata：实际结果独立审查

**原始 metadata 探针通过。** 同一完整请求、同一 key 协调到原 job `1a1acae0548-fc05-5655`，`reused=true`、`retried_launch=false`。首次 MCP 超时响应及 `submission-review-01` 均保留，没有改写成首次调用成功。

## 原生执行闭环

独立 status 为强 `succeeded / exit 0`，终态时间 `1793898485345 ms`（2026-11-05 17:08:05.345 UTC），115 B stdout、0 B stderr，完整持久、无截断、重试、取消或超时。原 stdout 从 bytes_hex 解码后为 `{passed:true, report:<固定报告路径>}`；实际计算确认 display text 与原始字节相等，显示层转义不是内容变化。

原 read_multiple_files 包装完整，单文件 eof=true、整体 truncated=false。UTF-8 正文重新计算为 **15,772 B**，SHA256 `93d2c3acc11247b86cb9d016a9df2facc6f06c1a01eab0a7fecb175058a85754`，version `2053:2373084:15772:1793898485299540628:1793898485299540628`；owner 本地 actual-report-01.json 也逐字匹配。该 SHA 来自后来读取的文件身份；原 115 B footer 仅含 path/passed，不冒充执行时 report SHA 承诺。

## 实际发现

| 项目 | 实际结果 |
|---|---|
| CPU | Intel Core i5-3230M @ 2.60GHz，GenuineIntel family 6 / model 58 / stepping 9 |
| 可见逻辑 CPU | 4；affinity 为 0、1、2、3；未据此声称物理核数 |
| 平台 | Linux x86_64，6.8.0-142-generic |
| rustc | 固定 1.95.0 sysroot 的直接二进制，SHA `bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6` |
| 元数据命令 | rustc -Vv、sysroot、default cfg、native cfg、target-cpus 五项全部 exit 0；capture complete、child reaped；全部 stderr 0 |
| 版本输出 | rustc 1.95.0 (59807616e 2026-04-14)，LLVM 22.1.2；196 B 原文与冻结版本 SHA 一致 |
| CPU 识别 | target-cpus 原文确认 native 当前识别为 `ivybridge`，且列出命名项 `ivybridge`；该 target 的默认 CPU 为 `x86-64` |
| llvm-profdata | 在唯一指定 sysroot 路径 unavailable；未搜索其他路径、未安装 |
| 磁盘快照 | available 3,267,739,648 B；不是 clean-build 空间预算或构建准入 |

已从原始 `command-logs-read-01.json` 完整读取五份 stdout 和五份空 stderr；十份正文合计 3,453 B，全部大小和 SHA 与实际 report pins 相同，版本中的 device/inode/size/mtime 也逐项对应。读取包装是 independent_file snapshot，不声称十份文件同时原子快照。

从两份 cfg 原文独立重算，native 相比无 target-cpu override 新增 13 项：`aes`、`avx`、`cmpxchg16b`、`f16c`、`pclmulqdq`、`popcnt`、`rdrand`、`sse3`、`sse4.1`、`sse4.2`、`ssse3`、`xsave`、`xsaveopt`。差集与实际 report 完全相同，反向差集为空。

target-cpus 原文明确写出 `native ... currently ivybridge`，并包含独立命名项 `ivybridge`；默认项为 `x86-64`。这里只执行过 `target-cpu=native --print cfg`，没有额外执行命名 `ivybridge` 的 cfg 或编译。两份 metadata cfg 中的 `debug_assertions`、`panic="unwind"` 只属于这些元数据调用，不能被解释为历史 release 构建参数。

## 绑定与边界

固定 R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`、三份绑定 receipt、220 项已知 source inputs 和 14,373,416 B runtime SHA `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13` 均通过探针绑定。仓库 `.cargo/config` 与 `.cargo/config.toml` 在该快照中均不存在。

metadata passed 只解决固定硬件/工具链调用可用性和已知绑定。它没有证明历史有效 Cargo flags、完整源码树、全机 llvm-profdata 不存在、清洁构建预算、编译变体资格、吞吐收益或跨机器可移植性。报告保持 `build_or_benchmark_executed=false`、`tools_installed=false`、`configuration_modified=false`、`compiler_variant_qualified=false`。

本审查只做本地证据读取和派生审查文件写入；零 native、GitHub、测试或探针执行，未修改 source 或 owner 文件。Owner 仍持有 reservation26，没有 handoff。
