# 最终候选 e425 的完整 CI 结果

Rust PR run [43701857912](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43701857912)
与 Cloud PR run [43701857874](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43701857874)
均为 completed/success，绑定候选 `e425d92b6a0dedf13eb3e484e76419ee756804c0`。
三个 job 共 59 个已报告步骤全部成功。

| 检查 | 精确候选 | 预合并版本 |
|---|---:|---:|
| Rust all-features | 2,633 passed，44 skipped | 2,633 passed，44 skipped |
| Rust no-default-features | 2,592 passed，32 skipped | 2,592 passed，32 skipped |
| Python unittest 摘要 | 937 run，936 passed，1 skipped | 869 run，869 passed，0 skipped |
| Release 构建及各自烟测 | PASS | PASS |

Cloud 离线测试另为 Router 46、Colab 69、Kaggle 76，合计 191/191 passed。
重复模式和重复 job 的执行次数不能解释为同样数量的不重复用例。
Python 的唯一 skip 位于 search-worker suite；非 verbose 日志没有打印原因，
按固定源码中唯一 skip 分支推断为缺少可选 pypdf，未把该项记为通过。
Rust skip 分别列出，未新增 ignore，也未重试失败测试。

[机器汇总](summary.json)、[最终全部步骤](final-jobs.json)、
[宿主限制复测](environment-retests.json)和各 job 的 counts JSON 可直接阅读。
[完整原始证据压缩包](complete-evidence.tar.gz)保存原封存目录全部 24 个文件，
包括三个完整日志、三个 GitHub artifact 原 ZIP 与 digest 验证、时间线、
计数脚本和原始 README。解压后的 README 相对链接指向包内原始文件。
本目录的 `source-README.md` 仅作原文副本，其相对原日志路径应在解压目录使用。

[原始逐文件清单](manifest.json)及[压缩包核对记录](archive-manifest.json)
记录文件数、字节数与 SHA-256。历史失败和取消仍保留在各自旧候选目录，
没有被本轮成功结果覆盖。
