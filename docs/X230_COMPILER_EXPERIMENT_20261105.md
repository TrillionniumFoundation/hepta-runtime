# X230 compiler experiment：原生 metadata 已验证

**状态：一次原生 metadata preflight 已完成；构建与性能候选仍未选择。** 原 job `1a1acae0548-fc05-5655` 在2026-11-05 17:08:05.345 UTC强终态 succeeded / exit0，完整115 B stdout、0 B stderr。首次start的MCP响应超时原件保留；同完整请求、同key协调复用了同一job，没有重启进程。五条rustc元数据命令全部返回0，十份原stdout/stderr均已按大小、SHA和version核对。

本次由原native执行所有者在reservation26窗口执行，没有执行权交接。source/cache inventory、compiler构建、训练、完整资格及性能测量次数仍为0；两个模板保持selected=false。本发布增加实际metadata及原始证据，未改变runtime源码、冻结工具、资格阶段或性能门槛。它是实验进展，不是已采纳的优化runtime版本。详见[实际结果与原件入口](../tools/x230/20261105/compiler-experiment/actual-metadata-01/README.md)。

## 历史及本检查点最后核实的已接受基线

| 身份 | 值 |
|---|---|
| 版本 | accepted R24 |
| 源码 commit | `baab4def80be7af015b2e7a594cb302f66c4130e` |
| 源码 tree | `b71cac25e2c2138837f27f3c74f6a2dc5c56b565` |
| 实际 runtime | 14,373,416 bytes |
| runtime SHA-256 | `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13` |

基线依据为本分支已有的 [R24 报告](X230_OPTIMIZATION_20261105_R24.md)、[原资格报告](../tools/x230/20261105/r24/reviews/qualification-report-01.json) 和 [220 项已验证源码映射](../tools/x230/20261105/r24/reviews/qualified-source-map-01.json)。本检查点增加实际metadata结果及证据，未重写旧源码、报告或数据。

这不是对未来候选基线的选择。如果 R28 或其他版本在选择前被采纳，必须建立新的固定输入，绑定当时 accepted 源码、实际 ELF、测试 inventory 和相符的 native metadata。原 R24 preflight 保留历史身份，不能改名或补写成新版本的实际证据。

R24 已声明 `opt-level=3`、`lto=true`（fat LTO）、`codegen-units=1`、`panic="abort"`、`strip=true`；这些 release 设置已经存在，不构成新优化。有限历史筛查未找到 CPU 专用编译、PGO 或 BOLT 的既有实测记录，但未穷尽所有历史。更具体的缺口是：资格报告记录了 Cargo 命令及输入身份，尚未建立每条最终 rustc 的完整 effective flags；原 qualifier 也未整族清除 `CARGO_PROFILE_*`、`CARGO_TARGET_*`、`CARGO_BUILD_*` 覆盖。不能从 Cargo.toml 或构建地点反推完整历史 target 设置。[历史核对](../tools/x230/20261105/compiler-experiment/reviews/compiler-optimization-history-01.md) 保留来源、范围和原结论。

## 实际 CPU、工具链与下一步

| 项目 | 实测元数据 |
|---|---|
| CPU | Intel Core i5-3230M @ 2.60GHz；4逻辑CPU，affinity 0–3 |
| rustc / LLVM | 1.95.0 (59807616e) / 22.1.2 |
| native识别 | `ivybridge`，来自原始target-cpus输出 |
| 工具链默认CPU | 当前target为 `x86-64`；只描述本次元数据调用 |
| 指定llvm-profdata | 所选sysroot路径 unavailable；未搜索其他位置、未安装 |
| 可用空间快照 | 3,267,739,648 B，约3.04 GiB；尚无clean-build预算 |

[实际report](../tools/x230/20261105/compiler-experiment/actual-metadata-01/report.json)为15,772 B，SHA256 `93d2c3acc11247b86cb9d016a9df2facc6f06c1a01eab0a7fecb175058a85754`。从[默认cfg](../tools/x230/20261105/compiler-experiment/actual-metadata-01/commands/toolchain_default.stdout)和[native cfg](../tools/x230/20261105/compiler-experiment/actual-metadata-01/commands/native.stdout)原文独立重算，native新增13项：aes、avx、cmpxchg16b、f16c、pclmulqdq、popcnt、rdrand、sse3、sse4.1、sse4.2、ssse3、xsave、xsaveopt；反向差集为空。原始[target-cpus](../tools/x230/20261105/compiler-experiment/actual-metadata-01/commands/target-cpus.stdout)明确识别native为ivybridge。没有另行执行命名ivybridge的cfg或编译。

这五条命令没有Rust源码输入，不执行Cargo、构建、链接或benchmark。cfg中的debug_assertions、panic=unwind以及默认/native差异，只描述本次metadata调用，不能补成历史R24 effective flags。仓库内两处Cargo配置路径均不存在，但没有据此声称覆盖全部Cargo自动发现来源或继承环境。指定llvm-profdata缺失也不能外推为全机无此工具。

下一步是依据实际source/public-cache inventory核清完整源码、公共依赖缓存和容量，再冻结可容纳的新构建recipe。220项编译映射不是完整source inventory；约3.04 GiB余量不是fresh-build预算。source/cache preparer仍未实现，没有因本次metadata通过而启动构建、训练或选择PGO/BOLT。未来若选择CPU专用产物，其部署范围必须另行绑定，不能假定适用于所有机器。

[精确请求协议](../tools/x230/20261105/compiler-experiment/native-requests-01/protocol.md)与[冻结preflight](../tools/x230/20261105/compiler-experiment/preflight-plan.json)保持原字节，包含执行前的历史准备措辞；实际执行由本节及[闭合记录](../tools/x230/20261105/compiler-experiment/actual-metadata-01/closure-01.json)说明。原失败、超时与同key协调均保留。

## 新增资格模板及本地检查

[外置资格 driver](../tools/x230/20261105/compiler-experiment/qualification-template-01/README.md) 保留原 8 个阶段、19 个 Python 工具、版权、完整测试 inventory 和零重试语义。新模板构造干净环境，分别绑定 target 目录与 triple，记录实际源文件、工具链、Cargo 配置、driver、native metadata 和产物身份。编译阶段保留 `-vv` 与 Cargo JSON；缺失或歧义的实际编译参数使证据闭合失败，不用计划中的 flags 补齐。第一版没有 wrapper 或旧编译 target 复用。

[输入模板](../tools/x230/20261105/compiler-experiment/qualification-template-01/input-template.json) 的未来绑定全部为 null，`selected=false`。[已保存的本地负向检查](../tools/x230/20261105/compiler-experiment/qualification-template-01/local-validation.json) 结果为 **exit 2，mutation/subprocess 调用 0**，仅证明未绑定模板在写入和子进程之前拒绝执行。本次发布副本没有重跑测试。独立的 [Cargo 静态审查](../tools/x230/20261105/compiler-experiment/qualification-template-01/root-review-cargo-01.md) 与 [admission 静态审查](../tools/x230/20261105/compiler-experiment/qualification-template-01/root-review-admission-01.md) 在限定范围内未发现明确阻断，但没有执行 selected 路径或验证实际编译日志的兼容性。

[资格设计](../tools/x230/20261105/compiler-experiment/candidate-qualification-design-01.md) 和 [私有准备设计](../tools/x230/20261105/compiler-experiment/preparation-design-01.md) 明确剩余工作：后续执行权协调、届时 accepted 身份、完整源码与 sparse registry 的独立准备、真实 checksum 和全新构建空间预算，以及固定输入后的完整资格。source/cache preparer 尚未实现；目录与 receipt 模板不能代替实际准备结果。

## 新增只读 inventory 模板

[inventory 包](../tools/x230/20261105/compiler-experiment/inventory/README.md) 有界记录所选 accepted source、原 harness 和公共 crates.io registry 输入的身份，不执行 Cargo/Rust、子进程、网络、复制、解包或缓存清理。[输入模板](../tools/x230/20261105/compiler-experiment/inventory/input.template.json) 仍是 `selected=false`，所有未来绑定为 null。[冻结 manifest](../tools/x230/20261105/compiler-experiment/inventory/manifest.json) 保留唯一一次实际本地未绑定拒绝：**exit 2**，未读取所选 source/cache 路径、未创建证据目录；selected/native 分支执行次数为 0。本次发布副本未重跑该检查。

sparse-index 只记录文件身份，尚未解析某个包版本的 `cksum`；归档与 Cargo.lock checksum 的比较不能代替该项。Cargo.lock 全集也不是实际 target/features/host-build 依赖闭包。观察得到的 registry map 可以含 checksum 不符项，不能当作复制允许清单或已准备好的私有 registry manifest。即使将来返回 `inventory_complete=true`，也只表示有界清点完成，不代表 preparation、离线解析、资格或构建通过。

实际源码/缓存 inventory 与 fresh-build 空间预算仍未知；本次metadata仅记录了一个约3.04 GiB的可用空间快照。16 MiB 只是证据输出上限，不是构建预算。[脚本](../tools/x230/20261105/compiler-experiment/inventory/inventory.py) 不能直接生成可供本轮 driver 采用的 preparation receipt。后续 preparer 仍需独立核对实际输入、副本、checksum 和容量，原 preflight、执行权协调、完整资格和验收门槛均不改变。

## 保持原评价边界

[compiler-screen-plan.json](../tools/x230/20261105/compiler-experiment/compiler-screen-plan.json) 保留既定观测改善/非退化、资源、C32/C6 correctness 和完整 lifecycle 门槛。本 checkpoint 没有改变或执行这些门。当前没有选定 CPU 专用构建、PGO 或 BOLT；训练若以后发生，也不能作为独立验证样本，原失败不能用不变候选反复重跑覆盖。

R27 serializer 仍是独立的组件实验，完整 runtime 未资格验证、未采纳；已拒绝的 R26 也不替换 accepted R24。这里没有合入两者的源码改动或混用其结果。preflight 的完成与否，更不能替代任何新编译产物的完整资格和原门槛验收。

完整文件入口见 [compiler experiment README](../tools/x230/20261105/compiler-experiment/README.md)。此前33文件版本的31个非入口文件均保留原字节；本次只更新两份入口说明，并新增实际metadata、原工具包装、十份命令输出及独立审查。所有runtime源码及既有冻结工具不变。原绝对路径继续作为来源数据保留，仓库浏览使用相对链接。
