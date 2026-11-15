# rmcp 3.9 STDIO framing 兼容性核对与测试修复

本目录记录候选 `0414c548c46a2e16a0b58e7595bde7a8c44359ea` 的 EOF framing 失败复现、仅测试修复、真实源码薄 harness 和静态检查。原托管 CI 的完整失败结果保留在独立 `pr125-ci-watch-0414c548` 目录；这里没有覆盖旧日志，也不把聚焦测试结果当作全仓 CI 通过。

## 实际兼容变化

rmcp 从 3.4.1 升到 3.9.0 后，`AsyncRwTransport` 将 `read_until` 改为有界 `read_line`。旧实现会先交付 EOF 前非空的最后一段字节，因此会接受一条完整 JSON 值，即使结尾没有 LF。新实现只在遇到 LF 时交付一帧；真实 EOF 使 `receive()` 返回 `None`，不交付没有 LF 的尾帧。这个变化发生在真实生产 transport，不是测试调用错了 `JsonRpcMessageCodec::decode/decode_eof`。

独立逐字节比较确认，两版完整 codec、helper、Decoder/decode_eof 和 Encoder 区域没有变化，SHA256 为 `9dd14883eeab5ae216ed7081f235327169f8addc911ee27db252dd408005bc75`。根因证据在 `independent-codec-root-cause.json`。

| 输入或边界 | 3.9 实际行为及本次处理 |
|---|---|
| 普通 LF 终止的 JSON-RPC | 继续接受；保留原 REA 参数顺序断言 |
| UTF-8 BOM + CRLF | 继续接受；保留原 REA 参数顺序断言 |
| 完整、有效的 JSON，但真实 EOF 前无 LF | SDK 与 REA adapter 均不交付；新增直接对照测试，明确记录历史接受行为的收紧 |
| 一条输入行超过 SDK 默认 16 MiB | SDK 丢弃该行，继续处理后继帧；真实超长有效 JSON 测试验证下一条 id 2 及其独立原始参数顺序，不允许前一帧污染私有 capture |
| 一条输入行超过 REA 10 MiB capture、但低于 SDK 16 MiB | SDK 可以交付，REA 的原始参数捕获仍拒绝；新增实际大小测试核对 `10485760-byte` 错误与缺失 raw keys |

16 MiB 是 SDK 对单条输入行的默认界限，长度计算包含终止 LF；它不是 REA 10 MiB raw capture 的替代。没有取消任一界限，没有给 EOF 注入虚拟 LF，也没有改生产 transport。使用 STDIO 的发送端应为每条消息写入终止 LF。已有不写 LF 就关闭输入的调用方式，会受到这次依赖升级影响。

[MCP 2025-11-25 transport 规范](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) 写明：

> Messages are delimited by newlines, and MUST NOT contain embedded newlines.

这条规范支持项目由 SDK 管理换行 framing 的约定；这里不把它当作旧 SDK EOF 实现细节的证明。EOF 差异的证据来自两版真实 SDK 源码、托管失败日志和聚焦复现。项目模块原有约定由 SDK 负责 framing，因此本次只调整旧测试对无 LF 尾帧的接受预期，并增加有界 reader 的真实边界覆盖。

## 修改范围

源码提交只修改 `src/mcp/rea_mcp_transport_tests.rs`，保留原 BOM/CRLF、原始参数顺序和其他旧断言。新增三个独立测试，生产文件、Cargo.toml、Cargo.lock、冻结 REA 输出与 fixture 均未修改。测试没有 ignore、重试或按宿主条件跳过。

`final-source-and-features.json` 与 `framing-tests.patch` 记录最终源字节、唯一变更路径和已解析特性。Cargo.lock 仍为 SHA256 `1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631`。

## 验证及证据边界

1. `01-baseline-eof-reproduction.log/.json`：原始未修改 test，通过真实 `ReaMcpTransport` 与真实 rmcp 3.9.0 复现同一个 `receive().expect("complete request")` 失败。1 项执行、1 项失败，退出 101；不是编译失败。日志与执行前后源 SHA 均保留。
2. `02-framing-regressions.log/.json`：修改后使用固定 nextest 0.9.137，全部 34 项真实 transport/structured-writer 测试通过，0 skipped、0 retries；每项独立进程，测试执行 2.168 秒。包含构建总耗时 9.696 秒。
3. `03-repository-format.*`：全仓 fmt 通过（退出 0，2.995 秒）。
4. `04-repository-clippy.*`：全仓 all-target/all-feature strict Clippy 在 90.055 秒后退出 101，lib-test 元数据检查进程遭 signal 9 / SIGKILL，无 Rust lint/type 诊断。该全仓检查未完成，不能计为通过；信号本身也不足以证明 OOM。保留完整原始日志，没有反复重试或修改 profile 绕过。
5. `05-focused-clippy.*`：对真实薄 harness 的 all-target strict Clippy 通过（退出 0，46.652 秒）。范围只覆盖本次修改涉及的源模块；harness 顶层允许独立构建产生的 dead_code，其他 lint 使用 `-D warnings`。不能代替后续全仓 CI。
6. `independent-framing-security-review.json`：独立审查唯一 test diff、真实模块、锁定依赖、原始失败与修复后 34 项日志。结论仍要求后续全仓 CI。

候选 0414 的两条托管 Rust lane 各执行 2630 项：2629 passed、1 个同名 EOF framing 失败、44 skipped。no-default nextest 和后续独立 Python/control/X230/release gate 被该失败阻断。本次聚焦通过没有补齐这些未执行 gate；最终合入仍须等待后续精确 head 与 prospective-merge 全部适用 CI。

## 薄 harness 的真实性

`harness/src/lib.rs` 按绝对路径直接引入原仓库的完整 `rea_mcp_transport.rs`、`rea_inline_order.rs`、`rea_structured_wire.rs`，以及它们原有 sibling tests。没有另写 transport、reader、codec 或 SDK 替身。writer 依赖的 `parse_unique_json`、`response_budget`、`Failure` 与 `RESPONSE_BYTES` 从原文件逐字节提取，仅为独立编译补齐 imports；源行范围和 hash 在 `harness-provenance-before.json`。

harness 包加 105 个依赖共 106 包。`harness-lock-review.json` 逐项确认所有非 harness 包的版本、来源和 checksum 均存在于项目最终锁中；不是另选一套 SDK 依赖。rmcp 特性包括生产 server/macros/transport-io/transport-streamable-http-server 与测试 client，serde_json 保持 float_roundtrip/raw_value。`final-source-and-features.json` 保存解析后的实际列表。

聚焦 harness 用独立 target、单构建任务，完整保留 commands、日志、退出码、运行前后源 hash。路径是原始执行证据，不是用户路径；若重现，需将 harness 中的源码路径指向相应 checkout。未访问真实主机、HIA、生产发布或真实云资源。
