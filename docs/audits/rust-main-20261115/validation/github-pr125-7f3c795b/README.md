# PR #125 首轮托管 CI：原始失败证据

本目录保留 2026-11-15 首轮 CI 的原始结果。后续修复或新提交的通过结果不能替换本目录中的失败日志；这里也不对尚未执行的步骤作通过声明。

## 源身份

| 项目 | 值 |
| --- | --- |
| PR | <https://github.com/TrillionniumFoundation/hepta-runtime/pull/125> |
| Exact head | `7f3c795b1dcbf22fd88f0bf8fe94e31fe019c0e9` |
| Exact head tree | `9bcf6f43cc432e63f8200a65aea98ba83a11efa1` |
| Prospective merge | `b88a4b7e913d9edc81bba0103485ecd40348aa14` |
| Rust run / attempt | `43686118845` / `1` |
| Rust run 完成时间 | `2026-11-15T07:21:22Z` |

两个 Rust job 均实际触发并通过各自的源身份检查，随后运行了格式、两种特性配置的 cargo check、两种特性配置的严格 Clippy 和完整 all-feature nextest。这里的“完整”指 workflow 默认选择的测试集合，不包括 nextest 报告的 44 项跳过测试。

## Rust 原始结果

| Job | 实际运行 | 通过 | 失败 | 另行跳过 | 测试耗时 |
| --- | ---: | ---: | ---: | ---: | ---: |
| [Prospective merge 132726838056](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43686118845/job/132726838056) | 2629 | 2626 | 3 | 44 | 191.270 秒 |
| [Exact head 132726838225](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43686118845/job/132726838225) | 2629 | 2626 | 3 | 44 | 237.483 秒 |

上述两行是同一测试集合在两种源身份下的两次运行，不代表 5258 个不同测试。默认日志没有列出 44 项跳过测试的名称，不能从这份日志单独推断每项跳过原因。测试二进制均编译成功，这两次托管运行没有出现本地此前的 rustc SIGKILL。

三个失败在两种身份中完全一致：

- `mcp::rea_contract::overflow_tests::every_missing_or_additional_overflow_member_keeps_the_prior_projection`
- `mcp::rea_contract::overflow_tests::observed_overflow_factory_matches_original_complete_error_text`
- `mcp::rea_contract::overflow_tests::unobserved_overflow_semantics_and_scalar_types_are_not_reclassified`

原始失败位置为 `src/mcp/rea_contract_overflow_tests.rs:62` 和 `:170`。失败来自合并后的错误响应文本投影契约：专用 overflow 编码器遇到不支持的形状时绕过当前 ELF/Evidence 通用错误投影；另一断言把已经改变的当前 `wire()` 当作冻结 native 捕获的历史序列化器。左右响应的 `content[0].text` 成员顺序不同。这是可定位的代码与历史测试基线组合问题，不是宿主能力限制。

两个 job 的后续无默认特性 nextest、Python 回归、release build 和 release smoke 因上游失败而跳过。因此，本地曾遇到的 AF_UNIX、`/proc` task children、Landlock 环境问题，在这轮 CI 中尚无复测结论；本地缺少可选 pypdf 的跳过也不能据此改为通过。

## Cloud 原始结果

| 事件 | Run / job | 结果 |
| --- | --- | --- |
| Push | `43686021948` / `132726550387` | Router 46、Colab 69、Kaggle 76 项全部通过 |
| PR | `43686118851` / `132726838001` | Router 46 项中 1 项失败；Colab、Kaggle 后续步骤跳过 |

PR 中失败的是 `RouterTests.test_claim_prevents_expiry_race_during_auth_with_stale_evaluation`，原始位置 `tools/cloud-compute/router/test_hepta_compute.py:749`，诊断为 `entered.wait(timeout=2)` 返回 false。独立后续诊断确认，原测试先创建 150ms 租约再写 SQLite 并启动线程，可能在进入认证屏障之前就合法过期；这次历史结果仍保留为失败。后续修复不属于本目录绑定的 head，不能在此计为重跑通过。

## 文件与边界

- 四份 `.log` 是 GitHub job 下载接口返回的完整解码日志，按取得的 UTF-8 文本逐字节保存，未删除失败或重排输出。
- 原始时间戳空行中的行尾空白也保留，因此 `git diff --check` 会对这些原始日志报告空白；不为消除这类提示而清洗执行证据。新增说明与 JSON 文件不含这些空白问题。
- `summary.json`、`initial-state.json`、`rust-jobs-final.json` 和 `observation-timeline.json` 保留原观察快照；`manifest.json` 是最初的原始文件哈希清单。
- `artifact-manifest.json` 覆盖交付目录的文件、字节数和 SHA-256；它本身不自引用。
- 日志中的绝对 scratch 路径是本次审计执行环境的证据路径，不是用户机器路径。
- 观察期间没有重跑、取消或修改工作流，没有操作 HIA jobs、真实生产主机、云任务或发布操作。

修复后的本地格式与 Clippy 结果另存于相邻 `rea-overflow-fix` 目录，其中包括最终 all-targets 元数据编译被 SIGKILL 的原始失败。生产库和二进制的 Clippy 通过不能代替修复后 head 的托管 Rust 测试。
