# CPU 编译候选资格设计 01 — prepared only

**建议采用外置、单独编号的原 qualifier 副本，保留原八阶段；只改环境、显式 target/CPU 参数、证据记录和 release 路径。首选不加 rustc wrapper。** 本文仅给实现模板的最小设计，没有选择 CPU、创建候选、运行 native/Rust/测试或填入未来资格/产物 hash。当前 metadata preflight 仍绑定历史 R24；已有 README、screen/preflight plan 均未改动。

## 1. 构建前的版本绑定条件

历史 R24 参考为 commit `baab4def80be7af015b2e7a594cb302f66c4130e`、src tree `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`、runtime SHA256 `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13`（14,373,416 bytes）。其220项源码输入、1645 passed/34 ignored/1679 selected只是历史事实。

**若 R28 或其他版本先被采用，compiler build 前必须新建一份固定计划**，重新绑定当前 accepted source commit/tree、完整 source map、实际 baseline ELF、原资格工具和测试 inventory/所有 hash。不得静默沿用 R24 的220项、测试数或 ELF 来声称对最新版本有增量收益；现有 R24 metadata/preflight 仍原样保留为历史检查。新计划和 native handoff 未闭合时，模板必须拒绝执行。

## 2. 原工具中需要处理的四个具体位置

已查原 `qualify.py`（7661 bytes，SHA256 `95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d`），其身份与实际 R24 report 的 harness_before/after 相同。[original_qualifier, r24_report]

| 位置 | 最小变更 |
|---|---|
| 42–54行环境构造 | 从允许清单构造环境，不继承任意 ambient env；清理后才注入已冻结的 `CARGO_ENCODED_RUSTFLAGS`。外层单纯设置 RUSTFLAGS/wrapper 会被原脚本清掉。 |
| 96–120行编译阶段 | clippy、test-build、release 加明确的 host `--target` 和 `-vv`；release 再保留 Cargo JSON。其余阶段、features、targets、offline/locked、测试执行器和审计不减。 |
| 122–126行 release 复制 | 原 driver 的 `--target` 参数是 target **目录**；新 triple 字段必须另命名 `--target-triple`。明确 target 后，产物从 `<target-dir>/<triple>/release/…` 取，不能回退旧 `<target-dir>/release/…`。 |
| report/tool 身份 | 保留原 report 字段和八阶段名，增加独立 driver/diff/recipe/evidence 身份。原19份 harness 文件可作为保留基准，但不能说新增执行 driver 仍与原19份全部字节相同。 |

新的 driver 放在候选源码树之外，保留原版权/SPDX，保存原脚本、精确 diff 和新脚本 SHA。这样源码的原 `source_map` 与19份工具快照仍可检查；新增构建输入由独立 manifest 明确覆盖。没有必要另造整套资格框架。

## 3. 干净且明确的构建环境

推荐构造一个小 allowlist：固定 PATH、原构建账户 HOME、LANG/LC_ALL；新的 CARGO_HOME/CARGO_TARGET_DIR；冻结 jobs（历史R24为2）、`CARGO_INCREMENTAL=0`、`RUST_TEST_THREADS=1`、`TOKIO_WORKER_THREADS=2`、Python隔离设置。若使用已 pin 的 rustup shim，仅重建已验证 RUSTUP_HOME/禁止自动安装设置。Cargo、rustc、clippy、rustfmt 和 sysroot/目标库身份由 metadata 实际证据绑定；缺少就不隐式安装。

不从外部复制任何未显式重建的 `CARGO_*`、`RUST*`、HEPTA/SSH、Python路径或编译/链接 preload/CC/CXX/flags变量。只记录构造出的允许清单与命令，禁止 dump os.environ。Cargo/Clippy自己在子进程中生成的内部变量属于正常工具链，不能误判为 ambient 污染。

在新driver完成清理之后，用 ASCII 0x1f 连接明确参数数组 `[-C, target-cpu=<metadata 后选择的值>]`，写入 `CARGO_ENCODED_RUSTFLAGS`；不要同时留下另一套RUSTFLAGS。现在 CPU 与 triple 都保持未选择。原 Cargo.toml 的 release O3/fat LTO/1 CGU/panic abort/strip保持不变；**不要把 O3、LTO 或 panic=abort 当成全局 Rust flags 注入 dev/test**，以免改变原测试profile/展开测试语义。最终 release 调用还要实证这些配置确实生效。

仅换 CARGO_HOME 不足以排除 Cargo 沿当前目录祖先读取的配置。需要绑定适用配置输入和相关安全字段，确认没有未审查的profile/target/linker/wrapper/forced-env覆盖；不得改全局配置来迎合实验。Cargo官方文档确认 encoded flags优先级、显式host target只把额外flags应用于target编译，以及配置的祖先查找；release `lto=true`对应fat LTO。[O1, O4]

第一版模板应采用最小的**未绑定配置存在即停止**规则：从实际Cargo cwd（完整复制的source根）向上到文件系统根，逐层只查 `.cargo/config` 与 `.cargo/config.toml` 是否存在，再检查私有CARGO_HOME的两种文件。只有明确not-found才可认定缺省；发现未绑定文件、符号链接、权限错误或不确定状态即停止，不读取/输出其中的秘密值，也不重命名或编辑用户配置。若之后确需配置，必须另建允许键审查及身份明确的新计划。现有metadata preflight仅覆盖source本地配置hash，未证明祖先/用户配置缺省；不能把它当作完整干净构建证据。也不悄悄换cwd加`--manifest-path`，因为这会改变原阶段argv/cwd和fmt处理。

## 4. 原八阶段保留方式

| 阶段 | 保留的动作与唯一必要差异 |
|---|---|
| format | 原 `cargo +<pin> fmt --all` |
| fmt-check | 原 `cargo +<pin> fmt --all -- --check` |
| harness-tests | 原 unittest discover；原19份工具和测试保留 |
| clippy | 原 offline/locked/all-targets/all-features/`-D warnings`；在 `--` 前增加 `--target <host-triple> -vv` |
| test-build | 原 all-targets/all-features/no-run/JSON；增加 `--target <host-triple> -vv` |
| isolated-tests | 原 retained-artifacts/source-manifest/timeout180执行流程；Cargo JSON中实际executable路径继续驱动复制和测试 |
| audit-isolated-tests | 原独立审计和退出码规则 |
| release | 原 all-features/release/bins/examples；增加 `--target <host-triple> -vv --message-format=json`，对应新输出布局 |

全部原 stage timeout、失败保留、零自动重试和selected/ignored inventory逻辑保留。使用构建时实际accepted版本的完整测试要求，不能把历史R24统计作为后续R28的固定数量。test-build留下的真实事件决定测试可执行文件，不按名字猜一个旧binary。三份release输出仍全部构建并绑定；不能偷偷用旧目录的jobctl/driver补齐。

## 5. 隔离与实际编译证据

未来获得handoff后，才在新的自有目录准备source、target、Cargo cache、driver、qualification output和evidence。生产Rust源码/Cargo.lock/manifest保持accepted原字节；资格前后比对全部source与工具。原八阶段包含format，任何实际字节变化都须先解释，不能继续称compiler-only。不得覆写旧产物或借共享硬链接改动原输入。

只把Cargo.lock所需且已验证的离线依赖缓存数据复制到私有Cargo home；不带旧target/fingerprint缓存，不带凭据文件，不隐式下载。复制的离线依赖源/index/archive缓存不证明CPU兼容，也不承诺减少native编译；新`--target`/CPU参数可能使大部分通用编译缓存失效，本设计本就不复用旧compiled target。实际baseline ELF单独只读绑定；新candidate每个测试/发布输出都用真实路径、长度和完整SHA记录。CPU专用runtime的可用范围不能推定到其他主机，jobctl/driver的部署身份要在计划中独立冻结。

最小证据组合是 **原始 `-vv` stdout/stderr + test/release Cargo JSON + 实际产物 SHA + source/config/driver 身份**，再保存存在的对应product fingerprint原字节作为佐证。Cargo JSON不是完整rustc argv日志；fingerprint的rustflags也不能单独证明整个profile。新鲜target中的root产物必须与本轮命令和artifact事件一一关联。实际flags缺失或歧义时不据计划补全。

`-vv`会包含build-script输出，JSON输出进入stdout；应保留并hash原日志，遵循既有发布扫描规则，不打印ambient凭据，也不为公开日志而抹掉失败结果。对final release核对选定CPU/target、fat LTO与1CGU；不要要求host proc-macro或测试编译也带release-only flags。[O2, O4]

## 6. rustc wrapper 是否可用

**可以有条件使用，但不作为第一版最小模板的默认项。** 仅在确需独立argv记录而现有编译日志不能闭合证据时，给新recipe增加一个pin过的`RUSTC_WRAPPER`，由新driver在清理后显式注入。原qualifier会清除外层wrapper，不能靠外层export让其“隐式生效”。

recorder只保存指定stage的argv/cwd/编译器身份，不保存环境；写入私有、每调用唯一的记录，然后以不改参数的exec交给实际编译器。记录失败应使本次构建失败。若覆盖Clippy，需要认识其合法driver链，不能套用只允许直接rustc路径的错误假设。

保持`RUSTC_WORKSPACE_WRAPPER`未设置。Cargo官方说明workspace wrapper影响artifact filename hash，R19历史还实际记录了unset/empty造成metadata/二进制变化。任何wrapper方案都要独立绑定路径/字节，在匹配control中保持相同处理；不声称相对旧R24完全中性。[O3, history_review]

## 7. 比较与采用边界

对实际accepted ELF的比较可以说明新产品是否满足原门槛。仅凭Rust源码相同不能把差异因果归结为CPU flag：历史R24完整effective flags未知，干净环境、显式target及构建布局也可能不同。要做CPU-only因果判断，需要metadata证明原配方等价，或另外固定、实际构建匹配control；本文没有选择额外control build。

现有 `compiler-screen-plan.json`（SHA256 `0bb6cec902402e7fda41b1fc9e763d92735ee74e00f801ed588196d5470b8997`）的全部数值门槛保持：observation ABBA C1/C8/C16，每档吞吐≥0.95、p95≤1.10；C8吞吐≥1.03且controller-own CPU/call≤0.97；RSS同时满足A+512KiB及A×1.05；原C32/C6正确性。lifecycle仍是原all_operations/launch/concurrent_cancel吞吐≥0.95、p95≤1.10、原每B phase/round一tick CPU容差与同样RSS；waited-child CPU不能替代own gate。

若accepted版本改变，只新建绑定计划，不重写旧preflight/结果，不调整数值门槛。本次下一步最多是本地实现带未填future绑定的driver模板；metadata、当前accepted版本和handoff未满足时必须拒绝执行。

## 来源

| ID | 文件 | SHA256 |
|---|---|---|
| original_qualifier | `/workspace/scratch/806ba5f52f94/r24-tested-source/tools/x230/20261028/qualify.py` | `95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d` |
| r24_cargo | `/workspace/scratch/806ba5f52f94/r24-tested-source/Cargo.toml` | `3121870fbf66f65ce6b1925b3500eae8a05fc2d8019a2694da7d6fe941ad4d28` |
| r24_report | `/workspace/scratch/806ba5f52f94/r24-results/qualification-report.json` | `bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971` |
| r24_source_map | `/workspace/scratch/806ba5f52f94/r24-publication-ready/tools/x230/20261105/r24/reviews/qualified-source-map-01.json` | `c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd` |
| r24_readback | `/workspace/scratch/806ba5f52f94/r24-results/final-publication-readback.json` | `38866c01fac54133c8a88e25bee90ea4a551e7273614f493bf44522a8273d3ca` |
| screen_plan | `/workspace/scratch/b96be991ab90/compiler-experiment/compiler-screen-plan.json` | `0bb6cec902402e7fda41b1fc9e763d92735ee74e00f801ed588196d5470b8997` |
| preflight_plan | `/workspace/scratch/b96be991ab90/compiler-experiment/preflight-plan.json` | `e86d525894768cf6cf56f5171094c02a324314505653594a651de23b34b84708` |
| history_review | `/workspace/scratch/b96be991ab90/remaining-cpu-scout/compiler-optimization-history-01.json` | `4d008a89396232c6dee02a7de98a08b7e1e3b7463d784869ff1a22aae4ac7a5b` |

官方文档只用于核对Cargo行为，不构成X230实际编译证据：

- O1: [Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags)
- O2: [cargo build options](https://doc.rust-lang.org/cargo/commands/cargo-build.html#display-options)
- O3: [Cargo environment variables](https://doc.rust-lang.org/cargo/reference/environment-variables.html)
- O4: [Cargo profiles / LTO](https://doc.rust-lang.org/cargo/reference/profiles.html#lto)
