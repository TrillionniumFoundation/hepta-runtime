# X230 compiler experiment：首个准备检查点

**状态：prepared-only。** 当前没有可用的独占 native slot，原运行会话仍持有 X230/Mac 的归档 I/O 窗口。preflight 尚未向目标主机上传、尚未执行；没有 compiler 实验构建、PGO 训练、性能结果、候选选择或采纳。首次 checkpoint 保存的是可审查的准备材料，不是新的优化收益版本。

## 已接受基线

| 身份 | 值 |
|---|---|
| 版本 | accepted R24 |
| 源码 commit | `baab4def80be7af015b2e7a594cb302f66c4130e` |
| 源码 tree | `b71cac25e2c2138837f27f3c74f6a2dc5c56b565` |
| 实际 runtime | 14,373,416 bytes |
| runtime SHA-256 | `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13` |

基线依据为本分支已有的 [R24 报告](X230_OPTIMIZATION_20261105_R24.md)、[原资格报告](../tools/x230/20261105/r24/reviews/qualification-report-01.json) 和 [220 项已验证源码映射](../tools/x230/20261105/r24/reviews/qualified-source-map-01.json)。本检查点只增加准备文件，未重写旧源码、报告或数据。

R24 已声明 `opt-level=3`、`lto=true`（fat LTO）、`codegen-units=1`、`panic="abort"`、`strip=true`；这些 release 设置已经存在，不构成新优化。有限历史筛查未找到 CPU 专用编译、PGO 或 BOLT 的既有实测记录，但未穷尽所有历史。更具体的缺口是：资格报告记录了 Cargo 命令及输入身份，尚未建立每条最终 rustc 的完整 effective flags；原 qualifier 也未整族清除 `CARGO_PROFILE_*`、`CARGO_TARGET_*`、`CARGO_BUILD_*` 覆盖。不能从 Cargo.toml 或构建地点反推完整历史 target 设置。[历史核对](../tools/x230/20261105/compiler-experiment/reviews/compiler-optimization-history-01.md) 保留来源、范围和原结论。

## 下一步只做 metadata preflight

取得原运行会话的明确窗口交接后，才可提交 [冻结 preflight](../tools/x230/20261105/compiler-experiment/preflight-plan.json)。其范围是绑定 accepted R24 的回执、源码和二进制身份，记录 CPU/affinity/磁盘元数据，并在唯一指定 Rust 1.95.0 sysroot 下查询版本、默认及 `target-cpu=native` 的 cfg、支持的 CPU 名称，以及指定路径下可选 `llvm-profdata` 的版本。缺少工具就记录不可用，不安装、不下载、不改用其他工具链。

这些命令没有 Rust 源码输入，不执行 Cargo、构建、链接或 benchmark。默认/native cfg 的差异只描述该次 metadata 调用，不能补成旧 R24 effective flags。仓库 Cargo 配置仅记录指定文件的存在性、大小和哈希，不输出配置正文、不读取继承环境，也不声称覆盖全部 Cargo 自动发现来源。将来若选择 compiler-only 构建，仍需另行冻结实际 recipe、环境、产物、资格及部署兼容范围。

## 保持原评价边界

[compiler-screen-plan.json](../tools/x230/20261105/compiler-experiment/compiler-screen-plan.json) 保留既定观测改善/非退化、资源、C32/C6 correctness 和完整 lifecycle 门槛。本 checkpoint 没有改变或执行这些门。当前没有选定 CPU 专用构建、PGO 或 BOLT；训练若以后发生，也不能作为独立验证样本，原失败不能用不变候选反复重跑覆盖。

R27 serializer 仍是独立的组件实验，完整 runtime 未资格验证、未采纳；已拒绝的 R26 也不替换 accepted R24。这里没有合入两者的源码改动或混用其结果。preflight 的完成与否，更不能替代任何新编译产物的完整资格和原门槛验收。

准备文件、原 manifest 与历史审查的入口见 [compiler experiment README](../tools/x230/20261105/compiler-experiment/README.md)。Python、三个 JSON 及两份历史审查保持原字节；其中历史本地/远端路径是来源记录，仓库浏览使用 README 中的相对链接。
