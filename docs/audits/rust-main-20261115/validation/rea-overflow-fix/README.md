# REA overflow 合并修复：本地检查与适用范围

修复提交：`9a36faebecd2891dcc6df587e4f8b780f1bb988f`，基于 PR #125 首轮提交 `7f3c795b1dcbf22fd88f0bf8fe94e31fe019c0e9`。修复提交的 tree 为 `843f8ab591b348b9ba663007e1c96dd8ebc5b092`。这里只记录本地检查；原始托管 CI 失败单独保留在相邻 `github-pr125-7f3c795b` 目录。

## 改动与冻结契约

本次仅修改三个 Rust 文件：

- `src/mcp/rea_contract.rs`：专用 overflow 编码器不能识别的形状委托当前 `wire()`，保留既有 ELF/Evidence 错误顺序及未知字段的完整回退；已识别的 overflow 编码路径不变。
- `src/mcp/rea_contract_overflow_tests.rs`：只有冻结 pre-fix native 捕获的历史基线显式使用 `wire_with_text(None)`。测试未知形状回退的 `prior_projection()` 仍比较当前 `wire()`。原始 fixture 哈希、完整结果、原文逐字节比较、修复前后文本不同与 payload 语义不变的断言全部保留。
- `src/mcp/rea_contract_tests.rs`：新增一项真实 ELF `producer/body-overflow` 捕获经生产 `wire_overflow()` 分派的回归，比较原始 `content.text` 字节、完整 content、元数据和错误标志；原有十个通用错误 oracle 场景保持不变。

两个独立只读审查分别核对了当前 ELF/general 错误顺序与 fallback 边界，以及冻结 native 捕获的历史排序和未知成员保留。两个 native 捕获的对象成员均为字典序；它们与原生产者顺序的 reference 捕获不同，因此历史基线不应再用合并后已经修正过的当前 `wire()` 重建。

`reviewed-summary.json` 将三个源码文件及两个冻结 fixture 的 SHA-256 绑定到修复提交；所有文件均与该提交逐字节一致。两个 fixture 与首轮 PR head 的内容也逐字节一致，未更新历史来源或原始响应。

## 实际本地结果

所有命令使用 Rust `1.95.0`、共享依赖缓存、`CARGO_BUILD_JOBS=1`、`CARGO_INCREMENTAL=0`；Cargo 使用 `--locked --offline`。没有运行 full lib-test codegen，也没有执行 Rust 测试用例。

| 检查 | 结果 | 能说明什么 |
| --- | --- | --- |
| 最终源码 `cargo fmt --check` | exit 0 | 三文件最终版本符合格式要求 |
| 最终源码 all-targets/all-features Clippy | exit 101 | `clippy-driver` / rustc 的 lib-test `--emit=dep-info,metadata` 进程被 signal 9 / SIGKILL 终止，没有 Rust 代码诊断；此项未通过 |
| 已提交修复的 production `--lib --bins --all-features` Clippy，`-D warnings` | exit 0，58.954 秒 | 生产库及二进制通过严格 lint/typecheck，不证明测试已执行 |
| 本地 Rust 测试执行数 | 0 | 等待修复后 head 的托管 nextest |

SIGKILL 原始日志完整保留。仅凭信号无法确定终止原因，不能把它归类为编译错误，也不能声称测试已通过。最终 all-targets 检查开始和结束时，所记录源码及 fixture 的哈希一致。

第一轮中间快照的格式和 all-targets Clippy 曾返回 exit 0；检查运行期间补入了最后一项 ELF dispatcher 回归，因此这轮通过结果仅按原样保存在 `attempt-01-intermediate`，不作为最终三文件快照的 all-targets 通过依据。随后对固定最终快照的检查才是 `attempt-02-final`。

## 证据文件

- `attempt-01-intermediate/`：第一次检查的原始日志与当时记录，明确属于中间状态。
- `attempt-02-final/`：固定最终源码的格式日志、Clippy SIGKILL 日志、前后源码哈希及原始命令结果。
- `production-only/`：修复提交的生产库/二进制 Clippy 日志及源 commit/tree 回执。
- `reviewed-summary.json`：人工核对后的结果解释、文件哈希与覆盖限制。
- `artifact-manifest.json`：本目录除清单自身外的文件长度与 SHA-256。

绝对 scratch 路径是本次审计的执行环境证据路径，不是用户机器路径。没有触及远端 refs、HIA branches/jobs、真实生产主机、云任务或发布工作流。没有重跑或取消原始失败 CI。
