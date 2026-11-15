# PR #125 候选 0414c548 的完整托管 CI 结果

本目录的三份完整日志、观察时间线、原始 README 和其他原始文件，全部保存在
[complete-evidence.tar.gz](complete-evidence.tar.gz) 中；总共 10 个文件，逐文件
SHA-256 已核对。压缩包及各文件哈希见 [archive-manifest.json](archive-manifest.json)。
`summary.json`、`failure-analysis.json` 和 `manifest.json` 同时提供可直接浏览的副本。

本目录绑定 head `0414c548c46a2e16a0b58e7595bde7a8c44359ea`、tree `9f4109bd1d1c6cd8be3d18169c4cda2c26f0b816`、GitHub prospective merge `57304a9dcca7651254d0e92c177b3c6e1193ccf6`。这是依赖安全补丁后的实际失败结果，不能用于放行，也不能用后续修复的结果覆盖。

| Workflow / lane | Run / job | 结果 |
|---|---|---|
| Rust exact-head | 43696649514 / 132758637664 | 2630 run，2629 passed，1 failed，44 skipped |
| Rust prospective-merge | 43696649514 / 132758637878 | 2630 run，2629 passed，1 failed，44 skipped |
| Cloud PR（精确 head） | 43696649526 / 132758573837 | Router 46 + Colab 69 + Kaggle 76，共 191/191 passed |

两 Rust lane 的唯一失败都是 `sdk_bom_crlf_and_final_line_at_eof_keep_their_behavior`，在真实 `ReaMcpTransport::receive` 返回 `None` 后触发 `expect("complete request")`。rmcp 3.9 的有界 reader 不再交付没有 LF 的 EOF 尾帧；旧 3.4 的 `read_until` 会先交付 EOF 前的非空字节。这是实际 STDIO framing 兼容性收紧与旧测试预期不匹配，不是测试调用错了 codec，也不是 frozen REA 输出字节、握手版本或宿主资源失败。完整细节见 `failure-analysis.json`。未生成 backtrace，原始日志只提供 panic 位置及建议启用 RUST_BACKTRACE 的行。

两 lane 的 fmt、两模式 all-target check、两模式 strict Clippy、pinned nextest 安装均成功。失败后 no-default nextest、独立 Python/control/X230 与 release/smoke gate 未运行；不能把 skipped step 当作通过，44 个 nextest skipped 也不计为 passed。Cloud lease race 回归明确 `ok`。

本次 diff 没有触及 `tools/cloud-compute/**` 或 Cloud workflow，故 path-gated Cloud push 不适用。本轮适用两个 workflow、三个 job。旧候选 `4767ddc0` 的 push 结果只在其独立历史目录保留。

`summary.json` 是最终机器可读结果，`observation-timeline.json` 保留逐轮 job/step 状态，`initial-state.json` 与 `final-runs.json` 提供 API 证据，三份 `.log` 保存完整原始 job 日志及其原始空白。`manifest.json` 为文件 SHA256 清单。日志中的 runner/scratch 路径是原始执行证据，不是用户路径。

观察者只读取状态/日志，未重跑或取消 workflow，未改远端 refs，未触及 HIA、真实主机、生产部署、发布或真实云计算任务。后续测试预期修复及薄 harness 证据位于独立目录，保留这次失败原状。
