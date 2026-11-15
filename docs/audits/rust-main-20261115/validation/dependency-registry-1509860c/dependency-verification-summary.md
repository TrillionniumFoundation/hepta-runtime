# 修复依赖锁的独立复核

**结论：固定 RustSec 数据库复扫为零命中；全部 registry 版本的官方索引核对通过。** 这两个结果分别验证已知公告匹配与 registry 元数据，不代替源码审计、编译测试或生产验证。

## 固定输入

- 冻结 Cargo.lock SHA-256：`1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631`。
- 官方索引采样区间：`2026-11-15T08:32:31.342037+00:00` 至 `2026-11-15T08:37:28.903654+00:00`。
- 输入文件取自 validation 的独立工作树；扫描结束后再次校验源锁，SHA-256 未变。
- Cargo.lock 共 362 个包，registry 包版本 360 个、唯一 crate 名 352 个；其余为本地 hepta-runtime 和 vendored ruzstd。

## 结果与覆盖

| 核对项目 | 结果 |
|---|---|
| 固定 RustSec advisory-db | `4ef2df8e806a65e2f1ecc14f56f51249062b23d6`，1,509 公告 |
| 修复后 cargo-audit | 退出码 0；0 漏洞、0 warnings；`--deny warnings`；ignore 空、无 OS/架构筛选 |
| 官方 sparse-index 获取 | 352/352 crate；最多 4 并发；每次响应的时间、HTTP Date/ETag、内容 SHA-256 均记录 |
| 精确锁定版本覆盖 | 360/360；覆盖缺口 0 |
| yanked 状态 | 360 个锁定 registry 版本均未撤回 |
| 校验和 | 360 个 Cargo.lock checksum 均与官方 index 一致 |
| 声明的 MSRV | 311 个版本声明值均 ≤ Rust 1.95；49 个未声明，逐项列出 |
| 源文件变动 | 此核对没有改动工作树、锁文件、源码或远端 |

## 锁变更范围

依赖包总数仍为 362，仅以下七个包记录改变。Cargo.toml 只有 tokio、rmcp、russh 及 dev rmcp 的四处版本下限改变；features 及其他配置完全相同。

| 包 | 原锁定版本 | 新锁定版本 |
|---|---|---|
| crypto-bigint | 0.7.5 | 0.7.11 |
| ctutils | 0.4.2 | 0.4.8 |
| rmcp | 3.4.1 | 3.9.0 |
| rmcp-macros | 3.4.1 | 3.9.0 |
| russh | 0.63.3 | 0.65.0 |
| rustix | 1.1.5 | 1.1.6 |
| tokio | 1.53.1 | 1.53.3 |

rmcp 新增了指向原已锁定 libc、sha2 的依赖边，未新增包；tower-service 仍保留。已直接确认 rmcp 3.9.0 的 HTTP tool_schema 实现改为每次查询 get_tool，没有旧版的无界 tool_schemas 缓存。OAuth 和 HTTP 客户端 transport features 仍未启用，russh RSA feature 仍关闭。

crypto-bigint 0.7.11 + ctutils 0.4.8 的选择同时覆盖官方后续 Thumb-1 安全修订，并避开已撤回版本；依据保存在初始审计目录的 registry-targeted-review.json。

## 初始锁对照与限制

将同一批已下载的官方索引响应用于初始 476 锁文件版本比较，没有额外网络请求。结果：原锁中唯一已撤回版本是 crypto-bigint 0.7.5；全部原锁 registry checksum 也一致。该对照有单独的 initial-lock-index-comparison.json，原 cargo-audit 退出码 1 的报告保持不变。

索引检查是一段时间内的逐条观察，不是原子 registry 快照；将来维护者仍可能撤回版本。校验和比较的是锁文件与官方索引，未重新下载并哈希所有 crate 源码归档。49 个版本没有声明 MSRV，不能由元数据推断编译兼容性；实际编译与测试由独立验证工作负责。本报告不扫描历史归档内其他锁文件，不对本地/vendor 代码授予漏洞清除证明。

完整机器证据位于 official-index-report.json；verification-summary.json 给出关键计数及证据文件 SHA-256。rustsec-after.json 和命令收据是验证工作原输出的逐字节副本。
