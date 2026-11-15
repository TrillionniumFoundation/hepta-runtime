# 初始候选依赖审计：4767ddc

结论：**6 项漏洞、2 项 unsound 告警，cargo-audit 退出码 1。** 未报告 unmaintained 告警。原始扫描结果保留，不以忽略规则清除命中。

## 固定输入与来源

- 候选提交：`4767ddc02e627d9c0d68e1e04fe555949a9e9c3b`。
- Cargo.lock Git blob：`dedd3b756d8bc9ce6dff45231757747ba2fb52c8`；SHA-256：`906874e2b8f3073863cad9a21ea08450f5b807eaa667365950a7b9faace5a365`。
- 工具：[RustSec 官方 cargo-audit 0.23.0 发布](https://github.com/rustsec/rustsec/releases/tag/cargo-audit/v0.23.0)，2026-11-10 发布；独立 scratch 目录安装，未全局安装。
- 官方 musl 资产 SHA-256 与下载文件一致：`sha256:4f01c74ed84b2dffd0b1d37012a62cdf2a92c96e25bdf8eec7fcc0d4d3eb7811`。
- 官方 [advisory-db](https://github.com/RustSec/advisory-db) 固定提交：`4ef2df8e806a65e2f1ecc14f56f51249062b23d6`；提交时间 `2026-11-13T13:33:03+01:00`；载入 1,509 条公告。
- 完整 Cargo.lock 交给工具扫描，工具统计 362 个依赖；没有架构/系统过滤；ignore 列表为空。

## 命中与修复版本

| 公告 | 依赖与锁定版本 | 官方 patched 范围 | 当前配置边界 |
|---|---|---|---|
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) | `crypto-bigint 0.7.5` | `>=0.7.6` | crypto-bigint 经默认启用的 remote-fs/russh 进入依赖图，并由 elliptic-curve、primefield、rfc6979 使用；运行时支持本地 ECDSA 私钥认证。实际泄漏取决于所选算法、是否在本进程运算秘密值、编译器、CPU 及攻击者的测时能力。本次没有对目标机器汇编或侧信道做利用验证，不将锁文件命中夸大为已证实密钥泄漏。 |
| [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html) | `ctutils 0.4.2` | `>=0.4.4` | ctutils 经 crypto-bigint、SSH key/cipher、digest 等进入依赖图。问题为秘密值相关分支；u128 比较还存在特定 32 位目标条件。当前 64 位构建不能消除通用 mask 生成问题，也没有目标机器侧信道可利用性的实测结论。 |
| [RUSTSEC-2026-0457](https://rustsec.org/advisories/RUSTSEC-2026-0457.html) | `rmcp 3.4.1` | `>=3.7.0` | 该问题属于 rmcp OAuth 客户端。当前依赖未启用 auth feature；相应模块受 cfg(feature = "auth") 限制，仓库没有 AuthorizationManager 调用。不能据此从完整锁文件审计删除告警。 |
| [RUSTSEC-2026-0461](https://rustsec.org/advisories/RUSTSEC-2026-0461.html) | `rmcp 3.4.1` | `>=3.6.0` | 候选的 HTTP 入口启用 StreamableHttpService，并支持 2026-07-28 协议。rmcp 的 tool_schema() 对任意名称（包括未知名称）写入无界进程级缓存；HTTP 400 也可能留存条目。新增 loopback 绑定和外层令牌认证阻止匿名请求抵达缓存，但持有令牌的客户端仍能触发内存耗尽；未运行破坏性 OOM 验证。 |
| [RUSTSEC-2026-0462](https://rustsec.org/advisories/RUSTSEC-2026-0462.html) | `rmcp 3.4.1` | `>=3.9.0` | 该问题属于内置 reqwest/Unix socket Streamable HTTP 客户端。当前正常构建及 dev 的 client feature 没有开启这些 transport features，仓库没有对应客户端构造调用；普通 client feature 不会隐式启用 HTTP 客户端 transport。 |
| [RUSTSEC-2026-0495](https://rustsec.org/advisories/RUSTSEC-2026-0495.html) | `russh 0.63.3` | `>=0.65.0` | 问题在 russh 的 agent server 跳过 Agent::confirm。当前仓库只连接外部 SSH agent（AgentClient）及使用本地私钥进行 SSH client 认证；没有实现或启动 russh agent server。该配置未发现所述触发路径，但依赖版本仍处于受影响区间。 |
| [RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html) | `rustix 1.1.5` | `>=1.1.6` | rustix 在该锁文件中只有 tempfile 直接依赖，tempfile 是项目 dev-dependency。tempfile 的现有调用没有匹配所列 xattr API；项目中的 xattr 操作使用 libc/Python，不是 rustix Buffer API。仍保留 unsound 告警并升级测试依赖。 |
| [RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html) | `tokio 1.53.1` | `>=1.51.6, <1.52.0`, `>=1.53.3` | tokio 是生产依赖。项目 src/tests 未发现 AsyncFd 使用；锁文件对应缓存中的 355 个依赖 src 目录（不含 tokio 实现本身）也未发现 AsyncFd 文本。4 个平台相关包源码不在缓存中。此结果只能用于静态风险分层，不能证明所有二进制/平台/间接调用均不可达；unsound 仍需升级。 |

## 执行与证据

实际命令在仓库之外运行，输入显式指向已提取的固定锁文件：

```text
cargo-audit audit --file <fixed Cargo.lock> --db <pinned advisory-db> --no-fetch --format json --deny warnings
```

`audit.json` 为未修改的机器报告，`audit-execution.json` 记录起止时刻、完整命令和退出码。`tool-provenance.json` 记录官方工具资产与数据库固定身份。`findings-assessed.json` 保存八项逐条边界、官方修复依据和公告 Git blob；`advisory-evidence/` 保存固定数据库中的八份原文。`dependency-paths.json` 保存锁文件依赖路径，`asyncfd-source-triage.json` 保存 AsyncFd 搜索的范围与缺失包。

## 范围限制

完整锁文件扫描仍遵循 cargo-audit 的依赖来源匹配规则；本报告不代替本地/path/vendor 源码的独立审查，也未扫描历史归档中的其他锁文件。此处的可达性说明是源码与 features 的静态判断，不是漏洞利用证明。没有运行活跃主机测试、耗尽内存测试或侧信道试验。官方 cargo-audit 0.23.0 的 `--no-fetch` 也禁止刷新 crates.io 索引；独立 CARGO_HOME 没有预置索引，因此完整锁文件的 yanked 状态未由该次扫描单独验证。后续定向检查两个官方索引条目确认原锁定 crypto-bigint 0.7.5 已被撤回，见下节。数据库 JSON 中 last-commit/last-updated 为 null，身份由独立 Git 提交记录绑定，不将 null 解释为最新性证明。

未修改候选、Cargo.lock、源码或任何远端。此初始报告不能改写成零漏洞；修复候选应使用新锁文件另存审计结果，保留该退出码 1 的历史证据。即使之后固定 RustSec 数据库匹配归零，也不表示整体 CVE clearance 或生产资格认证。

## 后续官方索引与版本选择复核

`registry-targeted-review.json` 另行保存 crypto-bigint/ctutils 的官方 sparse index 快照和摘要。crypto-bigint 0.7.0–0.7.8 当前均为 yanked；0.7.6–0.7.8 的撤回原因是 [上游 #1373](https://github.com/RustCrypto/crypto-bigint/pull/1373) 修复 `NonZero<T>` 乘法可能产生零的不变量错误所需的 API 约束修订。原锁定 0.7.5 也已撤回。

0.7.9 是满足公告 patched 范围的最早未撤回版本，但 [官方 CHANGELOG](https://github.com/RustCrypto/crypto-bigint/blob/master/CHANGELOG.md) 为 2026-11-08 的 0.7.11 列出额外 Thumb-1 常数时间安全修复（[#1391](https://github.com/RustCrypto/crypto-bigint/pull/1391)、[#1399](https://github.com/RustCrypto/crypto-bigint/pull/1399)），并要求 ctutils 0.4.8。建议修复候选选择 **crypto-bigint 0.7.11 + ctutils 0.4.8**；两者未撤回、MSRV 1.87，满足项目 Rust 1.95。该选择有上游安全修订依据，不把 Thumb-1 问题描述成本次 x86_64 主机已可利用。

这项定向核对没有覆盖其余锁定包的全部 yanked 状态，也不会改变原始 cargo-audit 的 6 漏洞、2 unsound 和退出码 1。
