# D2 首次完整资格验证

原作业 `1a1b0cc0f51-fc05-7301` 在 x230 上首次成功完成；原终态 exit 0，输出完整、持久且已确认发布，stdout 1111 B、stderr 0 B。没有自动重试。

八个原始阶段全部成功：format、fmt-check、harness-tests、clippy、test-build、isolated-tests、audit-isolated-tests、release。原始逐项测试实际为 **1651 通过、0 失败、34 忽略、1685 选中、0 重试**；原审计独立记录同一计数。原有 19 个工具未变。

本目录保留原 preparation、qualification report、source-map、完整 test summary / audit 及两个原生终态/日志回执。原回执保留 API 返回正文原字节；没有 JSON 重编码。完整逐项 gzip 日志归档正在独立收集，将在后续提交补入，不重新执行测试或审计。

## 实际测试源码

最终 compiler source-map 为 222 个输入、SHA256 `4bdbae5e8dea5d7534b5bde6961b44eaeaf5524553a788e171fee9fb2ecf5209`。本提交把原 formatter 产生的 `ssh_observation_profile.rs` 真实字节同步到源码树（26767 B，SHA256 `db3f4a427eb177611414959d824ce3991dc02db426332cc8ae3da6d2ed1e899d`）；`phase_cost.rs` 保持此前准备字节。完整前后 map 与原 qualification report、preparation、test manifest 对齐。D2 相对于已验证 D1 仍只有两个生产源码路径变化，无新增测试或依赖变化。

## 运行产物与后续状态

资格验证保存的诊断 runtime 为 14460184 B，SHA256 `ce071bf5216a0bb5a7ce5a6871c3020cf0537d659e1a3836d7655590f8754a98`；其两个辅助可执行文件的真实身份记录在 result-binding.json 和原 qualification report 中。

精确 CI、关闭诊断功能的普通构建，以及六机 C1 诊断尚待完成。D2 是诊断版本，当前没有性能优化或采用结论。已接受的生产基线仍为 R24 `baab4def80be7af015b2e7a594cb302f66c4130e`。D1 原 C1 流程失败的记录及其后续独立解释保持原状。
