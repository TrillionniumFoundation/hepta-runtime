# 默认分支与旧 Rust 引用清理

清理执行于 2026-11-15 12:24:00.099925 UTC 完成。实际执行器退出 0，状态为
`COMPLETE_MAIN_PLUS_SIX_HIA_REFS`。默认分支已改为 `main`，150 个删除目标均不存在，
远端精确保留 main 与六个 HIA／迁移依赖引用。

## 实际操作

| 项目 | 已观察结果 |
|---|---|
| 操作时 main | `737acf6f901e46c57b0b4374e323e0d1132e0d49` |
| 已验证候选 | `e425d92b6a0dedf13eb3e484e76419ee756804c0` |
| 执行计划 SHA-256 | `f55b2a8343498777bc674c2266caa190ebd061956a9986848d2c56f3aa25f1c5` |
| 执行脚本 SHA-256 | `ae47f1cb3ef42c3246733cd66e432efd1d3a3fa4f272b05c81d3e522cf059c29` |
| 默认分支独立确认 | main；12:23:00.119210 UTC |
| 原子删除开始／结束 | 12:23:12.843740／12:23:37.532618 UTC |
| 删除目标 | 149 个原始 Rust 引用加本次汇总分支，共 150 个 |
| 删除后剩余目标 | 0 |
| 保留引用 | main + 六个 HIA 引用，共 7 个 |
| 开放 PR | 121、122、124；均不依赖待删引用 |

Git 删除使用一笔 `--atomic` push，对每个明确目标指定原 SHA 的 lease；不包含 main
或任何 HIA 保留引用。默认分支 PATCH、PR 状态与 Git 引用事务不是同一原子事务，
因此执行前后另行保存完整快照。实际 main 合并身份、候选祖先关系和两个必需 CI
工作流都在执行中再次读取。

直接证据：[执行收据](execution-receipt.json)、[删除结果](atomic-delete-result.json)、
[删除后完整状态](post-delete-state.json)。后续 Chrome CI 修复或审计文档提交可以继续推进
main；这些不会改变本次删除所绑定的实际合并提交和历史保管关系。

## 失败预检与最小调整

原执行器的两次只读预检在读取历史 PR 列表时分别遇到超时和请求失败，均在默认分支
修改及引用删除之前停止。失败收据保留；第二次观察到 HIA request-context 的外部推进，
随后只更新保留快照，没有复位 HIA。

每页 25 条的只读试探也耗时 52.056 秒。最终只修改实时 open PR 检查：请求一个
100 条容量的第一页，必须返回少于 100 条且每条为 open；满页、异常状态、重复身份、
外仓 base 和缺失 head/base 数据均拒绝。实际三条完整结果在 14.538 秒返回。
固定 93 个旧 PR 的关闭仍由独立完整清单及逐项收据证明，未被此查询替代。

执行器其余函数逐字节不变。原 19 项安全 fixture 与六组新增边界通过；root 和独立
审查者均确认 diff 范围。调整后只读预检成功，原子 dry-run 退出 0，前后全部 157 个
引用符合计划，才进行正式操作。静态源码、差异、测试和独审见
[执行器静态包说明](../preparation/cleanup-open-inventory-static-review.json)。

## ROG 历史工作流的临时防护

历史工作流 `372929360` 包含 `always()` 硬件恢复步骤。删除 push 的 ref 行为不能作为
必然跳过该步骤的证明，因此只临时停用这个工作流设置，未改其文件或保护条件。

- 停用后 GET 确认为 `disabled_manually`：12:05:43.654792 UTC。
- 原子删除和引用核验完成后，恢复原 `active` 状态；GET 确认：12:26:01.790828 UTC。
- 仓库工作流完整时间窗口 12:05:40–12:26:40 UTC 返回三项、空尾页；ROG 新任务为 0，
  删除开始及以后的新任务为 0。另存 11:00 起上下文，不把旧 main/HIA 任务归因于删除。
- 没有 dispatch 或取消工作流，没有部署、运行硬件命令或重启运行主机。

见 [暂停收据](rog-pause-confirmed.json)、[恢复收据](rog-restore-confirmed.json)和
[工作流窗口核验](workflow-window-summary.json)。

## 独立回读与完整证据

独立检查在 12:25:20–12:27:05 UTC 执行 14 次 GET：两次分支清单均为七个引用，
main 树及双亲不变，六个 HIA SHA 与删除前一致；完整 109 PR 清单为
25／25／25／25／9，无重复，固定 93 项均 closed 且原 head/base/draft 身份不变。
HIA PR 121、122、124 仍 open/draft，关系不变；PR120 已关闭，其 anchor 引用保留。
见 [独立核验](independent-postcleanup-verification.json)。

[完整操作证据](operation-evidence.tar.gz) 包含 116 个来源文件以及内嵌 manifest，
共 4,210,364 来源字节。所有 archive 成员均逐字节回读核对。

- archive SHA-256：`32640c9deeb381656144b4457959d62b2a81a402bcb95ab2875457c82dfe61e7`
- [来源 manifest](operation-manifest.json) SHA-256：`e40d29b7d80334a9c701f0d8c81da62598415352d4e0cca0300d46bacd7d499d`
- [压缩包回读校验](archive-verification.json)

归档包括失败预检、成功 dry-run、全部 17 个实际执行记录、原计划及最新完整预清理
快照、ROG 防护、工作流窗口和独立最终核验。另存的
[macOS durable start 静态限制](macos-durable-start-static-limitation.json)区分实际超时、
已确认的历史记录扫描成本和未定位的具体超时原因。Chrome CDP 的额外失败和修复
在主审计的独立验证目录记录，不混入已封存的候选成功 CI。
