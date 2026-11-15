# PR #125 中间候选 4767ddc 的历史 CI 证据

对应提交：`4767ddc02e627d9c0d68e1e04fe555949a9e9c3b`。它在依赖修复之前，不能替代最终候选 `0414c548` 的验证。

## 已观察到的结果

- Cloud push `43692709541` 与 PR `43692722908` 均通过；每次 Router 46、Colab 69、Kaggle 76，共 191 项。
- Rust run `43692722905` 的预合并任务完成全特性测试：2,630 passed，44 skipped；随后在 no-default 编译期间取消。
- Rust 候选任务启动了 2,630 项测试，另有 44 skipped；取消前记录 2,073 条 PASS，但没有完整 suite 摘要，因此不记为整套通过。
- 两个 Rust 任务均未完成后续 release 验证。

新候选触发后，旧 run 在 2026-11-15 08:54:25 UTC 被并发策略自动取消。没有人工取消或重跑；这一取消与已观察到的代码失败分别分类。

## 完整原文与校验

[complete-evidence.tar.gz](complete-evidence.tar.gz) 包含原目录的完整 10 个文件，包括四份完整 job 日志、状态时间线、原始 README、最终 run 元数据和 manifest。压缩前后逐文件 SHA-256 已核对，日志中的取消错误和原始空白保持不变。

[archive-manifest.json](archive-manifest.json) 给出压缩包及各原始文件的 SHA-256；[summary.json](summary.json) 可直接查看最终分类。原目录的 manifest 也保留为 [manifest.json](manifest.json)，其中列出的日志与时间线位于压缩包内。

原始证据和最终候选的证据分开保存，未把本次部分通过或自动取消改写为最终候选通过。
