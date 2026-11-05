# Compiler candidate：fresh source / 私有离线 Cargo 准备设计

状态：**design-only，未实现 preparer，未进行 native 检查、复制、Cargo/Rust 执行或构建**。本笔记补充 [qualification 设计](candidate-qualification-design-01.md)，不修改已发布计划、原八阶段验收或性能门槛。R28 可能在实际构建前被采用；未来 accepted commit、源码、工具链、缓存、目标目录及容量预算均未绑定。历史 R24/R26 只提供接口证据。

## 1. 原准备器告诉我们的事

| 历史对象 | 已核实路径 / 行为 |
|---|---|
| R24 | `/home/qian/hepta-runtime-optimization-20261105-r23/source` 整树复制到同前缀 `r24/source`；另复制 `r23/target-build` 到 `r24/target-build`。 |
| R26 | `/home/qian/hepta-runtime-optimization-20261105-r25/source-02` 整树复制到同前缀 `r26/source`；另复制 `r25/target-build-02` 到 `r26/target-build`。 |
| 两者的 Cargo home | `/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02`；这是历史参数，**未检查其当前存在性、内容或可用性**。 |
| qualifier | 源码内 `tools/x230/20261028/qualify.py`；在源码根目录运行，使用 `/home/qian/.cargo/bin/cargo +1.95.0`，`--jobs 2`，离线锁定依赖。未来改用已设计的外部 driver，原 harness 保持不变。 |

原准备器的 `cache_bytes + 3 GiB` 针对复制旧编译缓存；不能用作本次空 target 的容量依据。原 `copytree` 也不是已验证的“无符号链接”复制证明。上述源文件及报告的字节数、SHA256 见 [机器可读证据](preparation-design-01.json)。

## 2. 完整源码与辅助输入

R24 map 的 **220 项**仅覆盖根目录 `Cargo.toml`、`Cargo.lock`、`rustfmt.toml` 以及 `src/**`、`examples/**`。本地 220 项 SHA 全匹配；可见源树共 282 文件，但这不是 native 完整树清单。必须另外绑定完整源树 manifest：保留全部已确认源码、测试/fixture、文档及脚本输入，不按 Cargo 打包 `exclude` 或 220 map 裁剪。

明确在 220 项之外且验收需要的是 `tools/x230/20261028/*.py` **19 个原文件**；它们的 SHA 与 R24、qualified R26 报告的 harness before/after 全部一致。脚本存在同目录导入及通过 `__file__` 找相邻 runner 的调用，不能只复制外部 qualifier。源码内 35 处字面量 `include_str!/include_bytes!` 共引用 20 个文件，均存在且已在 map 内，其中含全部 17 个 Python 内嵌源。

本地未见根 `build.rs`、`tests/fixtures` 或 README；`Cargo.toml` 却声明 `README.md`。这些是本地快照的边界，不证明 native 没有辅助输入，也不应补造文件。qualified R26 map 已变为 221 项，另增取消测试；其 Cargo manifest/lock 与 R24 相同。未来按届时 accepted 全树重新清点，不能固定使用 220/221 或旧测试数。

## 3. 最小缓存复制策略

采用“**独立源树 + 新私有 Cargo home + 空 target**”。Cargo 官方说明下载归档可重新展开，因此无需继承旧 `registry/src`；其内部缓存布局并非稳定接口。[Cargo home](https://doc.rust-lang.org/cargo/guide/cargo-home.html)

| 允许复制到新 Cargo home | 前提 |
|---|---|
| `registry/index/<已绑定 sparse namespace>/config.json` 与 `.cache/**` 的已清点普通文件 | 实查确认该 Cargo 版本识别的 public crates.io sparse 布局；保留元数据原字节、不改命名。检查锁定包 name/version/source/cksum 齐全；`config.json` 是 registry 元数据，不是 Cargo 配置覆盖文件；须为已绑定匿名公共端点。 |
| `registry/cache/<已绑定对应 namespace>/<name>-<version>.crate` | 仅复制 future lock 中 registry 包所需归档；逐包 SHA256 必须同时匹配锁文件 checksum 与 index 对应版本的 cksum。检查归档成员安全路径、根目录、类型、重复项和展开尺寸；拒绝符号链接、硬链接和特殊文件。 |

不复制旧 target、`registry/src`、`git/`、Cargo 配置/凭据、安装工具目录、安装记录、锁或全局缓存数据库。第一次受控 Cargo 阶段自行从已校验 `.crate` 新展开源码；旧 `.cargo-checksum.json` 不能代替对旧展开源码逐文件校验，因此这里根本不复用该树。

R24/R26 历史 lock 为 280 包（root 1 + crates.io 279），279 均有 checksum；这不是现存 cache 完备性证据。Lock 中 `registry+https://github.com/rust-lang/crates.io-index` 不能证明磁盘用了 Git index：Cargo 对 crates.io sparse 也使用该规范身份。[Registry index](https://doc.rust-lang.org/cargo/reference/registry-index.html) 第一版若实际只有 Git index、展开源码、未知布局、缺归档或需认证，就记录 **preparation blocked**；不复制 Git 配置、联网补包、改 source replacement 或临时迁移缓存格式。

## 4. 真正复制 / 构建前必须拿到的证据

1. **重新绑定基线与全树。** accepted 发布读回、源码 map、完整辅助输入 manifest、19 harness、Cargo manifest/lock 和外部 driver 的实际 SHA；保持所有原输入不变。若 accepted 在绑定后改变，另制新输入计划。源树中的 Git 管理数据、缓存或凭据不是源码输入；若与绑定清单冲突，停止核对，不静默漏文件。
2. **安全独立复制。** source / cargo-home / run_root 独占创建为 owned 0700；源码、缓存、构建和输出位置隔离且与旧输入不相交。交接 driver 时 target/output 必须不存在，由 driver 独占新建，首个 Cargo 阶段前 target 为空。源路径及成员须无符号链接，普通文件符合所有者/类型策略且 `nlink == 1`，拒绝特殊文件；读取前后 inode/stat/SHA 稳定。逐文件创建新副本，保留必要执行位；禁止硬链接复制。复制后重新核对 manifest、`nlink == 1` 及与原文件不同的 inode 身份，旧源及缓存复核不变。实际 namespace 与每个 index/archive 的 size/SHA 都须先绑定，不能仅凭历史目录名。
3. **配置和环境。** 外部 driver 继续使用已定的环境 allowlist。对实际 Cargo cwd 至 `/` 各层的 `.cargo/config`、`.cargo/config.toml` 及新 `CARGO_HOME/config{,.toml}`，仅明确 ENOENT 才算缺席；存在、链接、权限错误或身份未绑定即停，不读取/打印未知内容或改全局文件。新 Cargo home 的独占空目录和复制 allowlist 保证不引入 credentials。新 Cargo home 本身不能屏蔽祖先配置。[Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html#hierarchical-structure)
4. **容量及安静窗口。** 实际记录字节、分配空间与可用 inode；预算包括源码/index/archive 复制、归档展开、全新 debug+release/LTO 构建峰值、测试临时文件和证据日志及余量。清洁构建预算须有单独依据，当前数值为 null；复制前与构建前再查空间。R28 原 preparation 已因空间门槛失败：可用 6,285,365,248 B，旧 cache 3,080,991,421 B，加 3 GiB 后需 6,302,216,893 B，差 16,851,645 B（16.071 MiB）。这是旧复制方案的实际失败，不是新方案所需空间或当前可用空间。沿用 owner 的独占 admission，源/index 正被修改或其他编译干扰时停止，不清理任何现存数据或进程。
5. **交接与失败保留。** 外部 driver 接受实际 preparation receipt（新路径、全树和 harness manifest、cache allowlist/校验结果、空 target、配置检查、容量与所有未变输入），再开始原八阶段。仍用 `--offline --locked`；缺依赖是准备/验收失败，不能自动重试、放宽锁文件或转联网。[Cargo build](https://doc.rust-lang.org/cargo/commands/cargo-build.html#manifest-options) 静态清点不能冒充离线构建成功；测试、资源、吞吐与 adoption 结论仍须真实执行产生。

本次仅完成本地源码/报告对照及官方接口核查；没有 native inventory、复制、预解包、metadata 运行、构建、测试或收益结果。
