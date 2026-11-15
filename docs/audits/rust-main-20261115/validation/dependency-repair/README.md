# Rust 依赖安全修复与验证

源码提交为 `adb7ab1065011fafd9931e87ea32a30551776592`，基于 `710fc78f424138afa4e03c4a405258f37b31fc0e`。源码提交仅包含 `Cargo.toml`、`Cargo.lock` 和 `src/mcp/fs/remote.rs` 三个文件；本目录是独立验证证据，不改变运行流程或 CI 源码。

## 最终版本与最小变更

| 包 | 原锁版本 | 最终锁版本 |
| --- | --- | --- |
| rmcp | 3.4.1 | 3.9.0 |
| rmcp-macros | 3.4.1 | 3.9.0 |
| russh | 0.63.3 | 0.65.0 |
| tokio | 1.53.1 | 1.53.3 |
| crypto-bigint | 0.7.5 | 0.7.11 |
| ctutils | 0.4.2 | 0.4.8 |
| rustix | 1.1.5 | 1.1.6 |

总包数仍为 362；只有上述 7 个包记录变化，另外 355 个包记录不变，没有新增或删除包。rmcp 新增的 `libc`、`sha2` 依赖边指向原先已经锁定的包。`lock-delta.json` 保留完整逐包差异。

普通与 dev 两处 rmcp 声明均提高最低版本到 3.9.0，Tokio 提高到 1.53.3，russh 提高到 0.65.0；原有 feature 配置不变。生产依赖图中 russh 仅启用 `flate2`、`ring`，仍禁用默认功能和 RSA；未引入 `aws-lc`。rmcp 的 client feature 仍只来自 dev 声明，生产图没有启用 client、OAuth 或 HTTP client 功能。

## 版本选择中的实际发现

固定 RustSec 数据库的修复下限是 crypto-bigint 0.7.6 和 ctutils 0.4.4。但正常 Cargo 更新刷新官方索引后，确认 crypto-bigint 0.7.6、0.7.7、0.7.8 已被作者撤回发布。实际包约束还要求 ctutils `^0.4.5`，因此精确选择 0.4.4 的命令失败。这些原始探索日志完整保留。

最终选择 crypto-bigint 0.7.11 和它要求的 ctutils 0.4.8，是因为[官方 CHANGELOG](https://github.com/RustCrypto/crypto-bigint/blob/master/CHANGELOG.md)在 2026-11-08 的 0.7.11 条目明确列出了 Thumb-1 常量时间安全修复；0.7.9 仅解决先前导致撤回发布的 `NonZero<T>` 乘法不变量问题。没有从 x86_64 宿主的编译结果推断侧信道利用能力。

## 实际验证结果

所有本地 Cargo 检查均使用 Rust 1.95.0、独立 `runtime-dependency-target`、`CARGO_BUILD_JOBS=1` 和 `CARGO_INCREMENTAL=0`，保持仓库声明的 profile。除先前必要的精确更新和 fetch 外，检查使用 `--locked --offline`。

| 检查 | 结果 | 耗时 |
| --- | --- | ---: |
| 全部 Cargo 目标，all-features check | PASS | 199.607 秒 |
| 全部 Cargo 目标，no-default-features check | PASS | 116.310 秒 |
| `cargo fmt --check` | PASS | 3.694 秒 |
| 全部 Cargo 目标，all-features Clippy，`-D warnings` | PASS | 110.612 秒 |
| 全部 Cargo 目标，no-default-features Clippy，`-D warnings` | PASS | 98.973 秒 |

这里的“全部 Cargo 目标”指当前 Linux 宿主下的库、二进制、测试等 Cargo 目标，不表示对每一种 CPU 架构做了编译。每条检查回执都保存命令、退出码、耗时及三份最终源码的前后哈希；它们与源码提交逐字节一致。

**本地 Rust 测试执行数为 0。** 本次没有进行 full lib-test codegen 或 nextest；最终候选仍需要托管 CI 执行测试。旧 head `4767ddc0` 的运行结果不能替代新依赖锁的验证。

## RustSec 与官方索引覆盖

使用官方 cargo-audit 0.23.0、固定 RustSec 数据库提交 `4ef2df8e806a65e2f1ecc14f56f51249062b23d6`，在仓库外工作目录和独立空 `CARGO_HOME` 执行 `--no-fetch --format json --deny warnings`。结果为 exit 0、362 包、零漏洞、零警告、`ignore: []`。此结论限定于该数据库快照的匹配，不代表所有潜在漏洞都不存在。命令回执、工具和锁文件哈希见 `audit-after-command.json`；完整原始输出见 `audit-after.json`。

独立官方 sparse-index 审查另外核对了全部 360 个 registry 包版本，覆盖 352 个 crate：零撤回版本、零校验和不一致、零覆盖缺口。311 个声明 MSRV 的版本均不高于 1.95，另外 49 个未声明 MSRV，已明确单列。其余两个本地/path 包是 hepta-runtime 和 vendored ruzstd，不冒充 registry 校验对象。该独立报告原路径为 `/workspace/scratch/d72683e5e62a/rust-dependency-index-final-1509860c/official-index-report.json`，其锁文件哈希及报告哈希绑定在 `summary.json`。

最终锁文件 SHA-256：`1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631`。

## API 与安全边界复核

`independent-security-compatibility-review.json` 保存独立只读审查：未发现必须修改项目逻辑的 API 迁移点。项目没有直接 AsyncFd 调用，本次没有添加 unsafe。SSH 注释仅纠正原先关于证书签名验证的错误描述：默认不广告 host-certificate 算法；russh 的 KEX 签名证明不同于 CA 信任；现有 known_hosts/TOFU 策略不变。

rmcp 3.9 的 Host 默认与旧版相同，现有外层认证与 loopback 限制保留。项目显式使用 2026 协议，legacy 测试显式使用 2025-11-25；旧协议协商与 complete resultType 剥离规则保持。冻结 REA `content.text`、元数据和原始 fixture 未被改写。modern list/read 的保守缓存提示与 tools/call 错误响应分开记录，不能靠改 oracle 或关闭 guard 来消除潜在测试失败。

全部原始更新命令、成功与失败探索日志、编译检查和只读审查均保留。绝对路径是本次审计环境的证据路径，不是用户机器路径。没有修改远端 refs、HIA branches/jobs、生产主机、云任务或发布流程。
