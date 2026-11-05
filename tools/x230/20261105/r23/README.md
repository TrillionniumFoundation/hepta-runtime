# R23 证据索引：候选不采用

[结论与实测](../../../../docs/X230_OPTIMIZATION_20261105_R23.md)；分支生产源码保留 R22。R23 性能与资源改善通过原门，但取消/恢复失败，不能称为完整优化版本。

- [冻结测量计划](measurement-plan-01.json)
- [实际资格报告](reviews/qualification-report-01.json)、[简明资格结果](reviews/qualification-compact-01.json)、[220 项实际 source map](reviews/qualified-source-map-01.json)、[完整 Git/源码绑定](reviews/qualified-source-binding-01.json)
- [被拒候选的精确差分](rejected-candidate.patch)、[独立源码审查](reviews/source-review-01.json)
- [实际输入回执](reviews/campaign-inputs-01.json)、[终态失败 campaign](reviews/campaign-control-01.json)
- [原观测独立分析](reviews/native-analysis-01.json)、[容量独立分析](reviews/boundary-analysis-01.json)、[失败 campaign 的性能算术诊断](reviews/failed-campaign-performance-01.json)
- [取消/恢复原始失败报告](reviews/cancel-recovery-report-01.json)、[ROG 原始错误响应](reviews/failed-rog-response-01.json)、[Mac holder 终态及清理](reviews/mac-holder-01.json)
- [六个原 fixture 的只读终态核对](reviews/terminal-closure-01.json)、[其 Mac holder 回收记录](reviews/terminal-closure-mac-holder-01.json)、[只读核对工具](evidence-tools/terminal_closure.py)
- [launcher](campaign-tools/r23_campaign.py)、[原 summary 工具](campaign-tools/summarize_r23_campaign.py)、[资格准备工具](campaign-tools/prepare_and_qualify_r23.py)、[真实资格到输入回执工具](campaign-tools/prepare_campaign_inputs.py)

原 summary 工具因前序 lifecycle 失败而未执行；性能算术诊断只呈现已完成的 observation/capacity 结果，始终 `candidate_adopted=false`，没有替代全链采用门。

完整原始包已补齐：

| 原始包 | 字节数 | SHA256 |
|---|---:|---|
| [qualification-01.tar.gz](evidence/qualification-01.tar.gz) | 2,411,241 | `76478c6dae898e613b778ef097fa01f4434f0ead3a1c3e2a6b35ca0d97f7e8d2` |
| [campaign-01.tar.gz](evidence/campaign-01.tar.gz) | 3,098,136 | `c75ec3596bb74a3927e7194dfb388e5c5f6bdf6a15e9cbe96d128ab1f5093aab` |

85 个固定版本分片及两个整包的字节、SHA256 均已校验；tar QA 再逐一核对 7,464 个 payload 文件（38,630,135 B）。33 项省略正文只核对其实际远端身份元数据，没有在本地重哈希 ELF/私有 transport configuration/owned SSH wrapper 的正文。

[实际导出报告](reviews/export-report-01.json)、[分片和整包身份](reviews/archive-identities-01.json)、[完整 tar QA](reviews/archive-tar-qa-01.json)、[实际传输/Git blob 回执](reviews/archive-transfer-01.json)、[包内失败语义回读](reviews/archive-semantic-readback-01.json)、[核心拒绝记录的发布回读](reviews/failure-publication-readback-01.json)及[失败导出器审查](reviews/failed-exporter-review-01.json)一并保留。导出器的 `passed=true` 仅表示取证完整性；它同时保留 `campaign_passed=false`、`candidate_adopted=false`、原失败错误及缺失的全链 summary。没有重新测量。

工具：[失败取证导出器](evidence-tools/export_r23_failed_evidence_01.py)、[接收校验](evidence-tools/archive_receive.py)、[tar 全件校验](evidence-tools/archive_tar_qa.py)。
