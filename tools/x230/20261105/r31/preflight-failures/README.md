# R31 前置失败记录

这里保留原始失败结果，不把后续修复覆盖到原尝试中。两次主要失败分别发生在观察测量和补充 Rust CI 的前置检查阶段；它们均不能证明 R31 的整机吞吐、延迟、CPU、RSS 或饱和取消能力通过或退化。

原件、逐文件 SHA256 与本地核验范围见 [manifest.json](preflight-failure-originals/manifest.json)。归档脚本均只作为证据保留，本次本地复核未执行其中的脚本，也未提交远程工作负载。

## 1. 观察 attempt 01：旧 socket 目录前缀

Mac holder 原任务 `1a1ae37dda9-fc05-5e42` 以 `failed / exit 1` 完成，日志完整、持久化、无截断、无自动重试。原 holder 的 309 字节 stdout 明确记录远端退出码 1，以及所拥有的临时 SSH agent 已被回收；stderr 为 0 字节。

[父报告](preflight-failure-originals/observation-01/parent-report.json)记录开始于 `2026-11-06T00:17:40.527686Z`、结束于 `00:17:41.461538Z`，错误为 `private socket directory already exists`，`stages=[]`，没有 `quiescence` 记录。该报告 SHA256 为 `8fb90cf4358b210942343c9da76f40d3c3fe61d751c8c68ab00d65110abc46df`。

[原父脚本](preflight-failure-originals/observation-01/r31_campaign-original.py)仍用 `h30` 生成 `h30n01`、`h30b01`、`h30c01`。其目录新鲜性检查位于静置和所有 `run_stage` 调用之前，原错误正是在这项检查产生。结合空阶段列表，可以确认该尝试没有开始 90 秒静置，也没有执行观察、边界、取消恢复或性能汇总阶段。报告同时记录候选和基线源码输入未改变。

修复使用独立的 R31 attempt 02 目录，包括 `h31n02`、`h31b02`、`h31c02`，保留旧目录和原失败记录。新的测量结论必须来自后续实际执行的原始报告；这份失败记录不提供性能样本。

## 2. 补充 Rust CI attempt 01：工作流文件绑定错误

x230 原任务 `1a1ae4b6679-fc05-5ec3` 以 `failed / exit 1` 完成，完整保留 854 字节 stdout 和 1,071 字节 stderr，无自动重试。[原 traceback](preflight-failure-originals/exact-rust-ci-01/stderr.log)显示，materializer 在绑定 `source/.github/workflows/ci.yml` 时发现 SHA256 不同：

| 文件 | 字节数 | SHA256 |
|---|---:|---|
| [x230 源快照工作流](preflight-failure-originals/exact-rust-ci-01/remote-source-workflow.yml) | 7,235 | `5574840f604a3c7963a274592ac2468a43fdd04cdaa7122851c271188a11065d` |
| [已发布工作流](preflight-failure-originals/exact-rust-ci-01/published-workflow.yml) | 7,631 | `b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51` |

已发布文件与提交 `c039688312ceb09b3d26d1cdd50f9118eb11129f` 的 Git blob `34afc29edffd3130df158601c6a14fee5efbf79c` 一致，也与原 CI gate manifest 中的工作流身份一致。两份文件的全部差异，是已发布版本在两个 CI job 中各增加 `tools/x230/20261029` 和 `tools/x230/20261030` 的 Python unittest discovery 命令；Rust 命令没有变化。

[完整 stdout](preflight-failure-originals/exact-rust-ci-01/stdout.log)只有 `installed_exact_ci_tools` 和 `materialize` 两个阶段。[原 launcher](preflight-failure-originals/exact-rust-ci-01/tools/launch_exact_rust_ci_01.py)在 materializer 非零返回时直接退出，尚未到达执行 Cargo runner 的 `exec`；计划文件的写入也位于失败检查之后。因此这次任务没有执行 `cargo check`、nextest list 或 nextest run，不能记为 Rust 测试失败或通过。

修正应单独冻结已发布工作流，并保留源快照中原工作流的真实身份，使用新的工具、计划和输出路径。已通过资格的源码及二进制不因这次计划生成失败而被改写；GitHub 托管 Actions 状态仍须另行报告。

## 3. campaign 02 上传包装脚本的解析失败

安装准备中，原上传包装脚本少一个闭合大括号，两个提交 `1a1ae538f4b-fc05-5f08`、`1a1ae53d008-fc05-5f0b` 均在 Python 解析第 14 行时以 `SyntaxError / exit 1` 结束，stdout 为空。Python 尚未执行包装脚本正文，安装器和测量也未执行。[原代码、修正版与原 native/read 回执](preflight-failure-originals/campaign-02-installation/upload_wrapper_failure_01/)全部保留。

修正后的 x230 安装 `1a1ae54c8fd-fc05-5f13`、Mac 安装 `1a1ae54fc30-fc05-5f16` 和输入物化 `1a1ae555996-fc05-5f19` 均为 `succeeded / exit 0`，其[原回执](preflight-failure-originals/campaign-02-installation/remote-install-receipts/)一并保留。这些回执只证明工具和输入准备完成，不是测量重跑或测量通过的证据。
