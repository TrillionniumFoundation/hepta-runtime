# R36 scratch cold-02：实际资格结果

原作业 `1a1b1cb4862-fc05-7ad9` 已 succeeded / exit 0，完整 durable 输出为 1,125 B stdout、0 B stderr。原八阶段全部 returncode 0：

`format → fmt-check → harness-tests → clippy → test-build → isolated-tests → audit-isolated-tests → release`

原 isolated summary 与完整 audit 一致：**1,647 passed、0 failed、34 ignored、1,681 selected、0 retries**；audit `success=true`、`errors=[]`、executed 1,647。此为 cold-only 新空 target，未复用、复制或 rename D2 cache。

本目录七份 JSON 为已核 SHA 的原字节，保留原路径结构；native terminal/read 没有解析后重写或修正数字。本次发布只读取和比较 JSON，没有重跑原 auditor、资格或构建。

## 实际格式化源图

实际 [source-map.json](qualification-01/source-map.json) 与冻结 pre-format map Git `1f74b162be6e947b1c6b548594783f06c5c5a509` 都含 220 个相同路径，无增删。**相对该冻结 map，只有测试文件一处 formatter 差异，profile.rs 未再变化**：

- 路径：`src/mcp/runtime/ssh_observation_reference_tests.rs`。
- pre-format SHA256：`79d8d7e369e84bb853ab75930fc6a74a44bd519dc1be2f10bb7bba3b0b175dc0`。
- 实际通过的 SHA256：`0895a19b655fcb9abbd5fbbc479b8e1c719eadc0185a06e97add539a402d5dce`。

该差异位于原两文件候选范围内；不能把“候选相对 R24 的两处改动”误写成“formatter 又改了两处”。原 report.source_input 与 preparation.before 等于冻结 map；report.source_tested / source_after 与 preparation.after 均等于实际 map。冻结 pre-format 包和先前失败尝试继续保留，发布源码应以这份真正通过测试的格式化字节为准。

**资格通过不等于 exact CI、完整性能或生产采纳通过。** 这些结果分别保留自己的原作业与门槛。
