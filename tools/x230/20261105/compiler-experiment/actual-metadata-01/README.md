# X230 原始 compiler metadata：已完成

原生 job `1a1acae0548-fc05-5655` 于 **2026-11-05 17:08:05.345 UTC** 强终态 succeeded / exit 0。首次 start 的 MCP 响应超时保存在原件中；同完整请求、同 key 协调返回同一 job，`reused=true`、`retried_launch=false`。完整 stdout 115 B、stderr 0 B，持久保存，无截断、自动重试、取消或进程超时。

本次由原执行所有者在 reservation26 窗口执行，未交接 native 执行权。只运行五条固定 rustc 元数据命令；没有编译、训练、性能测量、工具安装、配置变更或清理。source/cache inventory 与 compiler qualification 尚未执行。

## 实际结果

| 项目 | 原始结果 |
|---|---|
| CPU | Intel Core i5-3230M @ 2.60GHz，family6/model58/stepping9 |
| 逻辑 CPU / affinity | 4 / 0,1,2,3 |
| 编译器 | rustc1.95.0 (59807616e)，LLVM22.1.2 |
| native 识别 | target-cpus 原文为 ivybridge；列表另有命名 ivybridge 项 |
| 默认目标 | 当前 x86_64-unknown-linux-gnu 的默认 CPU 为 x86-64 |
| 指定 llvm-profdata | 所选 sysroot 下该路径 unavailable；没有搜索其他路径 |
| 可用磁盘快照 | 3,267,739,648 B，约3.04 GiB；不是 clean-build 预算 |

从原始 cfg 独立重算新增13项：aes、avx、cmpxchg16b、f16c、pclmulqdq、popcnt、rdrand、sse3、sse4.1、sse4.2、ssse3、xsave、xsaveopt；反向差集为空。实际执行的是 `target-cpu=native --print cfg`，没有另行执行命名 ivybridge 的 cfg 或编译。

两份 cfg 的 debug_assertions / panic=unwind 和本次默认目标，只说明这两次元数据调用，不能追认历史 R24 的有效 Cargo flags 或 release 设置。已绑定 R24 的220项已知输入不是完整 source tree inventory；3.04 GiB 可用空间也不能证明新构建可安全容纳。没有性能收益、候选资格或跨主机可移植性结论。

## 原件与核对

- [实际 report](report.json)：15,772 B，SHA256 `93d2c3acc11247b86cb9d016a9df2facc6f06c1a01eab0a7fecb175058a85754`。
- [独立闭合记录](closure-01.json)：11个原始工具包装、两个原生job、10份命令输出与每份大小/SHA/version。
- [独立审查](actual-review-02.md)及[JSON](actual-review-02.json)：同请求协调、原始终态、源码/脚本身份、实际CPU与cfg差集。
- [首次 start 超时](originals/probe-start-01.json)、[同 key 协调](originals/probe-start-reconcile-01.json)、[原 status](originals/probe-status-01.json)、[原完整 read](originals/probe-read-full-01.json)。
- [原 report 读取](originals/report-read-01.json)和[原十份命令输出读取](originals/command-logs-read-01.json)。读取语义为各文件独立快照，不是十文件原子快照。
- [rustc版本](commands/rustc-version.stdout)、[sysroot](commands/rustc-sysroot.stdout)、[默认cfg](commands/toolchain_default.stdout)、[native cfg](commands/native.stdout)、[target-cpus](commands/target-cpus.stdout)。五份对应stderr均为空，原文件仍保存。

原 report、命令输出和工具包装保留原字节。报告中的原绝对路径为来源身份；本目录相对链接用于仓库浏览。source/cache inventory、clean-build预算、独立准备、完整资格和原性能门槛仍需实际执行；如果随后采用R28或其他版本，新的编译候选必须重新绑定届时accepted，不能重标本次R24证据。
