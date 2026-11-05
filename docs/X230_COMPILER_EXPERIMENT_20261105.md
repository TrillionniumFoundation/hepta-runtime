# X230 compiler experiment：只读 inventory 准备检查点

**状态：prepared-only，selected=false。** 本 compiler experiment 的 native metadata、构建、训练、资格执行和性能测量次数均为 **0**。preflight 尚未上传或执行，没有新候选选择或采纳。当前执行所有者的 reservation 25 已替代此前 reservation，仍未释放；本检查点不声称已取得 native handoff。冻结包中的旧 reservation 引用保留为历史准备记录，当前协调以 reservation 25 为准。此次在既有资格模板、准备设计和精确请求之上，只增加 source/public-cache inventory 模板及入口说明；它是工具准备检查点，不是新的优化 runtime 版本。

## 历史及本检查点最后核实的已接受基线

| 身份 | 值 |
|---|---|
| 版本 | accepted R24 |
| 源码 commit | `baab4def80be7af015b2e7a594cb302f66c4130e` |
| 源码 tree | `b71cac25e2c2138837f27f3c74f6a2dc5c56b565` |
| 实际 runtime | 14,373,416 bytes |
| runtime SHA-256 | `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13` |

基线依据为本分支已有的 [R24 报告](X230_OPTIMIZATION_20261105_R24.md)、[原资格报告](../tools/x230/20261105/r24/reviews/qualification-report-01.json) 和 [220 项已验证源码映射](../tools/x230/20261105/r24/reviews/qualified-source-map-01.json)。本检查点只增加准备文件，未重写旧源码、报告或数据。

这不是对未来候选基线的选择。如果 R28 或其他版本在选择前被采纳，必须建立新的固定输入，绑定当时 accepted 源码、实际 ELF、测试 inventory 和相符的 native metadata。原 R24 preflight 保留历史身份，不能改名或补写成新版本的实际证据。

R24 已声明 `opt-level=3`、`lto=true`（fat LTO）、`codegen-units=1`、`panic="abort"`、`strip=true`；这些 release 设置已经存在，不构成新优化。有限历史筛查未找到 CPU 专用编译、PGO 或 BOLT 的既有实测记录，但未穷尽所有历史。更具体的缺口是：资格报告记录了 Cargo 命令及输入身份，尚未建立每条最终 rustc 的完整 effective flags；原 qualifier 也未整族清除 `CARGO_PROFILE_*`、`CARGO_TARGET_*`、`CARGO_BUILD_*` 覆盖。不能从 Cargo.toml 或构建地点反推完整历史 target 设置。[历史核对](../tools/x230/20261105/compiler-experiment/reviews/compiler-optimization-history-01.md) 保留来源、范围和原结论。

## 下一步只做 metadata preflight

与当前 native 执行所有者协调后，有两条执行路径：由该所有者在自己的窗口内按 [精确请求协议](../tools/x230/20261105/compiler-experiment/native-requests-01/protocol.md) 执行 [冻结 preflight](../tools/x230/20261105/compiler-experiment/preflight-plan.json)，或在明确交接窗口后由我们执行。原所有者自行执行无需转移执行权；目前两条路径都没有产生本 compiler preflight 的实际执行。请求包包含 create-only 私有父目录、脚本原字节写入、文件身份查询和单一稳定 key 的执行请求，均未执行。原 preflight 的范围是绑定历史 accepted R24 的回执、源码和二进制身份，记录 CPU/affinity/磁盘元数据，并在唯一指定 Rust 1.95.0 sysroot 下查询版本、默认及 `target-cpu=native` 的 cfg、支持的 CPU 名称，以及指定路径下可选 `llvm-profdata` 的版本。缺少工具就记录不可用，不安装、不下载、不改用其他工具链。

这些命令没有 Rust 源码输入，不执行 Cargo、构建、链接或 benchmark。默认/native cfg 的差异只描述该次 metadata 调用，不能补成旧 R24 effective flags。仓库 Cargo 配置仅记录指定文件的存在性、大小和哈希，不输出配置正文、不读取继承环境，也不声称覆盖全部 Cargo 自动发现来源。将来若选择 compiler-only 构建，仍需另行冻结实际 recipe、环境、产物、资格及部署兼容范围。

## 新增资格模板及本地检查

[外置资格 driver](../tools/x230/20261105/compiler-experiment/qualification-template-01/README.md) 保留原 8 个阶段、19 个 Python 工具、版权、完整测试 inventory 和零重试语义。新模板构造干净环境，分别绑定 target 目录与 triple，记录实际源文件、工具链、Cargo 配置、driver、native metadata 和产物身份。编译阶段保留 `-vv` 与 Cargo JSON；缺失或歧义的实际编译参数使证据闭合失败，不用计划中的 flags 补齐。第一版没有 wrapper 或旧编译 target 复用。

[输入模板](../tools/x230/20261105/compiler-experiment/qualification-template-01/input-template.json) 的未来绑定全部为 null，`selected=false`。[已保存的本地负向检查](../tools/x230/20261105/compiler-experiment/qualification-template-01/local-validation.json) 结果为 **exit 2，mutation/subprocess 调用 0**，仅证明未绑定模板在写入和子进程之前拒绝执行。本次发布副本没有重跑测试。独立的 [Cargo 静态审查](../tools/x230/20261105/compiler-experiment/qualification-template-01/root-review-cargo-01.md) 与 [admission 静态审查](../tools/x230/20261105/compiler-experiment/qualification-template-01/root-review-admission-01.md) 在限定范围内未发现明确阻断，但没有执行 selected 路径或验证实际编译日志的兼容性。

[资格设计](../tools/x230/20261105/compiler-experiment/candidate-qualification-design-01.md) 和 [私有准备设计](../tools/x230/20261105/compiler-experiment/preparation-design-01.md) 明确剩余工作：实际执行权协调、当前 accepted 身份、native metadata、完整源码与 sparse registry 的独立准备、真实 checksum 和全新构建空间预算，以及固定输入后的完整资格。source/cache preparer 尚未实现；目录与 receipt 模板不能代替实际准备结果。

## 新增只读 inventory 模板

[inventory 包](../tools/x230/20261105/compiler-experiment/inventory/README.md) 有界记录所选 accepted source、原 harness 和公共 crates.io registry 输入的身份，不执行 Cargo/Rust、子进程、网络、复制、解包或缓存清理。[输入模板](../tools/x230/20261105/compiler-experiment/inventory/input.template.json) 仍是 `selected=false`，所有未来绑定为 null。[冻结 manifest](../tools/x230/20261105/compiler-experiment/inventory/manifest.json) 保留唯一一次实际本地未绑定拒绝：**exit 2**，未读取所选 source/cache 路径、未创建证据目录；selected/native 分支执行次数为 0。本次发布副本未重跑该检查。

sparse-index 只记录文件身份，尚未解析某个包版本的 `cksum`；归档与 Cargo.lock checksum 的比较不能代替该项。Cargo.lock 全集也不是实际 target/features/host-build 依赖闭包。观察得到的 registry map 可以含 checksum 不符项，不能当作复制允许清单或已准备好的私有 registry manifest。即使将来返回 `inventory_complete=true`，也只表示有界清点完成，不代表 preparation、离线解析、资格或构建通过。

实际源码/缓存 inventory、当前余量和 fresh-build 空间预算仍未知；16 MiB 只是证据输出上限，不是构建预算。[脚本](../tools/x230/20261105/compiler-experiment/inventory/inventory.py) 不能直接生成可供本轮 driver 采用的 preparation receipt。后续 preparer 仍需独立核对实际输入、副本、checksum 和容量，原 preflight、执行权协调、完整资格和验收门槛均不改变。

## 保持原评价边界

[compiler-screen-plan.json](../tools/x230/20261105/compiler-experiment/compiler-screen-plan.json) 保留既定观测改善/非退化、资源、C32/C6 correctness 和完整 lifecycle 门槛。本 checkpoint 没有改变或执行这些门。当前没有选定 CPU 专用构建、PGO 或 BOLT；训练若以后发生，也不能作为独立验证样本，原失败不能用不变候选反复重跑覆盖。

R27 serializer 仍是独立的组件实验，完整 runtime 未资格验证、未采纳；已拒绝的 R26 也不替换 accepted R24。这里没有合入两者的源码改动或混用其结果。preflight 的完成与否，更不能替代任何新编译产物的完整资格和原门槛验收。

完整文件入口见 [compiler experiment README](../tools/x230/20261105/compiler-experiment/README.md)。本次在此前 29 文件版本上只新增 4 个冻结 inventory 文件；原 27 个非入口文件保留原字节，包括脚本、计划、请求、设计、JSON、diff、负向检查和审查记录。只修改本入口文档与 compiler experiment README。原绝对路径继续作为来源数据保留，仓库浏览使用相对链接；没有加入新的 native、资格或性能结果。
