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

完整 qualification/campaign 原始包由伴随取证提交追加。所有源码、调用记录和可发布工具保留；ELF、私有 transport configuration 与 owned SSH wrapper 的正文只保存实际远端身份，不公开其正文。省略内容不声称在本地重新哈希。
