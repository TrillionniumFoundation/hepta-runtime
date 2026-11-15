# 编译优化历史核对：accepted R24（有限只读）

## 结论

**R24 已声明 O3、LTO、单 codegen unit、panic abort 和 strip。** Cargo.toml 的本地字节与 R24 资格报告 `source_input`、`source_tested`、`source_after` 中的 SHA256 一致；实际 release 阶段也有成功的 Cargo 命令回执。该事实不能提升为“已逐条观察最终 rustc 参数”。本轮未找到 actual product fingerprint 的 `rustflags[]` 或完整 rustc argv。

在限定的本地文档、资格回执和构建材料中，尚未发现 X230 `target-cpu=native`/指定 CPU、Rust PGO 或 BOLT 的候选与实测记录。也有限筛查了同一既有 docs 目录中的 R11 以前报告，结果相同。这里只记录搜索范围内的证据状态，不声称这些方向从未做过，也不保证它们有收益。

## 1. Cargo 配置与实际执行证据

| 层级 | 已确认内容 | 证据边界 |
|---|---|---|
| Cargo release 配置 | `lto=true`、`codegen-units=1`、`panic="abort"`、`strip=true`、`opt-level=3`、`overflow-checks=false` | 本地 Cargo.toml 与资格输入三张 map 的 hash 相同。[r24_cargo, r24_qualification] |
| 实际 Cargo 命令 | `cargo +1.95.0 build --offline --locked --all-features --release --bins --examples`；returncode=0；jobs=2 | 已记录的是 Cargo stage command；命令没有显式 target-cpu、PGO 或 BOLT 参数。[r24_qualification] |
| 实际发布 runtime | 14,373,416 bytes；`bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13` | 身份来自原资格/compact/output receipts；本轮未重读远端 ELF。[r24_compact, r24_output_identities] |
| 每条 rustc 调用 / effective flags | 本轮已检材料没有相应记录 | 不能据此确认完整 codegen、linker、target 或 profile 覆盖后的结果；未检查 target 缓存或归档。 |

Cargo.toml：3097 bytes，SHA256 `3121870fbf66f65ce6b1925b3500eae8a05fc2d8019a2694da7d6fe941ad4d28`。资格报告：83365 bytes，SHA256 `bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971`。原 release stderr 的记录 SHA256 为 `5be8281e1f465d9c6b08d1563797c6d6168ccd3aac8eecffd01d94d4b3b20576`；这里只读取了报告中的身份，未打开原归档取日志。

## 2. 已绑定 qualifier 的环境处理

`qualify.py` 的 SHA256 为 `95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d`，与报告的 `harness_before`、`harness_after` 一致。该脚本先复制继承环境，再选择性删除，最后把所得 `env` 明确传给每个 Cargo stage。[r24_qualifier]

| 行为 | 字段 |
|---|---|
| 删除的前缀 | `HEPTA_*`、`SSH_*`、`RUST_TEST_*` |
| 删除的具体变量 | `RUSTFLAGS`、`CARGO_ENCODED_RUSTFLAGS`、`RUSTDOCFLAGS`、`RUSTC_WRAPPER`、`RUSTC_WORKSPACE_WRAPPER`、`PYTHONPATH`、`PYTHONHOME`、`RUST_LOG` |
| 明确设置的构建变量 | `CARGO_HOME`、`CARGO_TARGET_DIR`、`CARGO_BUILD_JOBS`（本次 2）、`CARGO_INCREMENTAL=0` |
| 该 qualifier 未整族删除 | `CARGO_PROFILE_*`、`CARGO_TARGET_*`、`CARGO_BUILD_*` |
| 该 qualifier 未明确删除的相关名字 | `RUSTC`、`CARGO_BUILD_RUSTC`、`CARGO_BUILD_RUSTC_WRAPPER`、`CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER` |

外层 `prepare_and_qualify_r24.py` 调用资格脚本时没有传 `env=`，沿用自身启动环境。它会复制隔离的 R23 source/build cache 并绑定其来源；这些操作没有提供完整的 effective Cargo 配置快照。[r24_prepare]

**可以支持的结论：** 被回执绑定的代码会删除两个主要 Rust flags 环境变量，再启动 Cargo。**仍缺少的结论：** 祖先目录或 CARGO_HOME 的配置、target/profile/build 环境覆盖、实际逐 crate rustc 参数和 product fingerprint 尚未被本轮材料证明。不能把“在 X230 构建”或可执行文件名 `native_process_driver` 当成 `target-cpu=native` 的证据。

## 3. 相关历史与没有找到的记录

| 方向 | 本轮找到的历史 |
|---|---|
| O3 / LTO / one unit | R5–R7 已记载 optimization level 3、LTO、one codegen unit；R13 和 R16–R18 延续这些 release 设置。开启相同选项不能作为新的优化。[r5_r7_report, r13_report, r16_r18_report] |
| 编译环境处理 | R13 报告明确说当时启动器移除 `CARGO_PROFILE_*`、`CARGO_TARGET_*`、`CARGO_BUILD_*`；这是当时的证据，不能推定当前 R24 外层也执行相同处理。[r13_report] |
| wrapper 空值与缺省 | R19 保存了第一轮被拒绝的产物，以及 unset/empty/unset 诊断。空的 Cargo wrapper 设置改变 workspace metadata/产物身份；该诊断没有声称 runtime 性能优化。[r19_report] |
| R20 request-hash 组件 | 两个已存在组件 build 回执都为普通 `cargo +1.95.0 build --release --offline --locked`；runner 明确构造环境，未设置 RUSTFLAGS。它们比较 hash 实现，不是编译选项 A/B。[r20_probe_runner, r20_probe_build, r20_probe64_runner, r20_probe64_build] |
| target-cpu=native / 指定 X230 CPU | 在本轮限定材料中没有发现对应 flag、构建身份或 matched runtime 对照；actual product `rustflags[]` 未找到。 |
| PGO | 未发现 profile-generate/profile-use、llvm-profdata、profile 归档身份、合并记录或已资格验证的 PGO 产物。 |
| BOLT | 未发现工具版本/命令、输入 ELF 元数据、训练 profile 或改写后产物的资格与比较记录。 |

R20/R21 独立优化报告文件名未在本轮限定文档清单中命中；R20 组件材料不能代替完整 runtime 资格证明。未扩大搜索归档、未打开/解压已有 archive、未搜索编译缓存。这些缺口决定负面结论只能写作“当前本地材料尚未发现”。

## 4. 若继续 metadata preflight，最低先决证据

以下是证据要求，没有在本轮执行。它们不改变任何既有资格、正确性、吞吐、延迟、资源或采用门槛。

| 方向 | 最低先决条件 |
|---|---|
| 所有 compiler-only 方案 | 固定 accepted R24 source/lock 与实际工具链身份；记录有效 Cargo config、相关 flags/profile/target/wrapper 环境，并区分 unset/empty；能够绑定实际 product fingerprint/编译调用；明确哪些输出仅用于 X230、哪些需要运行于其他主机。现有 `--bins --examples` 会构建多个产物。 |
| CPU 选项 | 先取得并绑定 X230 CPU/target feature 元数据与部署兼容范围，再冻结唯一明确的编译选项差异和隔离产物；不能按编译地点猜测当前 target CPU。 |
| PGO | 先证明匹配的 instrumentation/profile runtime/merge 工具可用；固定有限训练工作负载和独立比较工作负载，保留 raw/merged profile 与告警身份；分别绑定 instrumented、profile-use 和 baseline 的构建/产物。当前只做 metadata，不生成 profile 或编译。 |
| BOLT | 先核对选定工具与原 ELF 的可重写信息、符号/重定位是否适配。`strip=true` 是现有配置，不能单独证明 BOLT 可行或不可行；如需额外构建输入，应另行绑定。最终要针对改写后的精确二进制重新完成资格与原比较门槛。 |

## 5. 有限范围与来源身份

最终负面关键词检查覆盖 31 个明确文件，`target[-_]cpu / profile[-_]generate / profile[-_]use / llvm[-_]profdata / llvm[-_]bolt / PGO / BOLT` 命中为 0。完整清单、hash 与查阅边界见同名 JSON。整个任务为本地读取；0 native/RPC、0 web、0 编译、0 安装、0 测试、0 新候选；新写入仅为本报告两份文件。

| ID | 文件 | bytes | SHA256 |
|---|---|---:|---|
| r24_cargo | `/workspace/scratch/806ba5f52f94/r24-tested-source/Cargo.toml` | 3097 | `3121870fbf66f65ce6b1925b3500eae8a05fc2d8019a2694da7d6fe941ad4d28` |
| r24_qualifier | `/workspace/scratch/806ba5f52f94/r24-tested-source/tools/x230/20261028/qualify.py` | 7661 | `95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d` |
| r24_prepare | `/workspace/scratch/806ba5f52f94/benchmark-r24/prepare_and_qualify_r24.py` | 6093 | `c76956cd24e3ffe8f78fe188ecb51041828c0de1e924c96329dd93bd742f87a8` |
| r24_qualification | `/workspace/scratch/806ba5f52f94/r24-results/qualification-report.json` | 83365 | `bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971` |
| r24_compact | `/workspace/scratch/806ba5f52f94/r24-results/qualification-compact.json` | 2325 | `184713b11ef53a660cd1e30da7a91261f53977f3fb75e8cb375bda53003b0401` |
| r24_review | `/workspace/scratch/806ba5f52f94/r24-results/qualification-review.json` | 4095 | `0e30bb5082d1c023d9b660910cb6a0831cf6b821261c397f2f19f1c9db35786c` |
| r24_closure | `/workspace/scratch/806ba5f52f94/r24-results/source-binding-qualification-closure.json` | 7307 | `135fbe672b72b1d142731d6452ac4a9089161dc969d9ec49596375efabbbbe05` |
| r24_output_identities | `/workspace/scratch/806ba5f52f94/r24-results/qualification-output-identities.json` | 2806 | `180fe8eee2484a61c310f4c41a0e745a8e1e651f6687a6715a38faa9f2033cdb` |
| r24_report | `/workspace/scratch/806ba5f52f94/r24-publication-ready/docs/X230_OPTIMIZATION_20261105_R24.md` | 14254 | `0bec7ea604e28832489c6a1338760aec77ea3eca22d65d868d6aae1f3b126dc2` |
| r13_report | `/workspace/scratch/846f8b2ab644/r20/audit-transport/docs/X230_OPTIMIZATION_20261103_R13.md` | 20362 | `d57428c4ec064f2d86557474381663956b3f075a25e514f9598b71b67a34abd5` |
| r16_r18_report | `/workspace/scratch/846f8b2ab644/r20/audit-transport/docs/X230_OPTIMIZATION_20261104_R16_R18.md` | 33427 | `31305eefb0917156bd666cd579ce60a8ec477da5db981c662054483715974ac0` |
| r19_report | `/workspace/scratch/846f8b2ab644/r20/audit-transport/docs/X230_OPTIMIZATION_20261104_R19.md` | 29952 | `494c1aae283a6313c48b867cecedac446c1bb326b3d9f115eb82eb141aa39b2f` |
| r5_r7_report | `/workspace/scratch/846f8b2ab644/r20/audit-transport/docs/X230_OPTIMIZATION_R5_R7_20261030.md` | 87086 | `73762efb0d1c62562c6f686419e621576b49d8dadc72f1e478423e18b607a201` |
| r9_report | `/workspace/scratch/846f8b2ab644/r20/audit-transport/docs/X230_OPTIMIZATION_20261031_R9.md` | 34897 | `631582cfbd1b2c5e6d0ecf98e1d71120cc90e650adf61191172a95dde669fbb5` |
| r20_probe_runner | `/workspace/scratch/846f8b2ab644/r20/audit-transport/hash-probe/run_probe.py` | 12935 | `0efc43a17e2d95606174990d8eefedfaf95d162c15bdcd824f8d715a1899d83b` |
| r20_probe_build | `/workspace/scratch/846f8b2ab644/r20/audit-transport/hash-probe-results-01/received/probe/04-build.stage.json` | 584 | `43a0719cb87f1b97d46aac1427bfd9d0d5608cfda1487c8b6b59d36d70fa5047` |
| r20_probe64_runner | `/workspace/scratch/846f8b2ab644/r20/audit-transport/hash-probe-64b/run_probe.py` | 12953 | `c29e111308fcd40ede1361a7c3d5329ba8391908462405bc803dd8abbb2e19c8` |
| r20_probe64_build | `/workspace/scratch/846f8b2ab644/r20/audit-transport/hash-probe-64b-results-01/received/probe/04-build.stage.json` | 584 | `cf6abacef191cf68169d70c75d3e75743088607bfa7f4fc66d9a0abed808923c` |
