# PR 完整清单与清理保管补充说明

本说明准备在候选工作树之外，仅补充清单、来源和统计修正，不改动当前候选提交、源码或 CI 输入。

候选：`4767ddc02e627d9c0d68e1e04fe555949a9e9c3b`。
完整直接 REST 采样时间：`2026-11-15T08:06:48.663Z`。

## 初始统计应如何表述

原始 `open-prs-before.json` 保留的是 GitHub search **观察到的 79 个 open PR**，包括 76 个 Rust PR 和三个受保护 HIA PR。它是不完整的搜索快照，不能再表述为仓库当时的完整 PR 清单。原文件应保留原样，新增本补充记录，不改写先前观察。

建议将审计 README 的初始统计措辞修正为：

> 初始分支快照包含 155 个远端分支；最初 GitHub search 观察到 79 个 open PR。后续直接 REST 完整分页发现搜索漏掉了 17 个既有 Rust PR。当前直接 REST 共返回 109 个 PR，其中 97 个 open：93 个待整合清理的 Rust PR、三个保留的 HIA PR，以及本次汇总 PR #125。

直接分页使用 `/repos/TrillionniumFoundation/hepta-runtime/pulls?state=all&per_page=30&page=N`，四页分别返回 30、30、30、19 项。其余 12 个 PR 为 closed。

额外 17 个 PR 都早于本次收拢，其 head/base 名称和 SHA 与原始 155 分支清单、当前远端引用一致。所有 head 都已是当前候选的祖先；它们是搜索漏项，不代表新建分支或未整合的新源代码。

## 额外 17 个既有 Rust PR

| PR | Head | Base | 已覆盖的处置 |
| --- | --- | --- | --- |
| #78 | `feature/rea-native-foundation-20261102` / `d54654c3b028` | `hepta-runtime-base` / `ba574f2a6a1b` | REA Rust 基础已在冻结基线中；沿后续 REA 整合演进。 |
| #91 | `feature/native-wsp-guard-20261104` / `d85852b3c170` | `feature/weight-workbench-seven-20261103` / `1f2d3d782e88` | 有限权重规划与受控编辑，随 semantic-certificate 谱系主动整合。 |
| #92 | `feature/wsp-trust-region-20261105` / `e7a2688acc55` | `feature/native-wsp-guard-20261104` / `d85852b3c170` | 共同 trust-region / F32 预算约束，随 WSP 谱系主动整合。 |
| #93 | `feature/wsp-bellman-journal-20261105` / `990f85e46bed` | `feature/wsp-trust-region-20261105` / `e7a2688acc55` | 有限 Bellman 规划与持久恢复，随 WSP 谱系主动整合。 |
| #94 | `feature/wsp-exact-certificate-20261105` / `bc38fb82244b` | `feature/wsp-bellman-journal-20261105` / `990f85e46bed` | 精确 continuation 不可行性证书，随 WSP 谱系主动整合。 |
| #95 | `fix/wsp-feature-pr-ci-20261105-db06` / `a5457dd63044` | `feature/wsp-exact-certificate-20261105` / `bc38fb82244b` | 堆叠 feature 分支 CI 过滤器保留在当前双 lane 工作流中。 |
| #96 | `feature/wsp-native-semantic-replay-20261105-628b` / `f9c121fa54c4` | `fix/wsp-feature-pr-ci-20261105-db06` / `a5457dd63044` | checkpoint 语义重放及原始算术修复，随 WSP 谱系主动整合。 |
| #97 | `experiment/x230-r30-router-20261105` / `7e3a08d549c6` | `perf/x230-r11-20261103` / `86155fbf3b89` | R30 未采用实验；精确源变体及拒绝证据归档，不启用旧 router。 |
| #98 | `experiment/x230-r31-pidfd-20261105` / `6757eff31093` | `perf/x230-r11-20261103` / `86155fbf3b89` | R31 未采用 pidfd 实验；精确源变体及证据归档。 |
| #99 | `experiment/x230-r33-path-components-20261106` / `080f4335ed34` | `perf/x230-r11-20261103` / `86155fbf3b89` | R33 被拒绝的路径组件实验；源变体与失败证据归档。 |
| #100 | `experiment/x230-r34-cancel-reserve-20261106` / `a649198a0484` | `perf/x230-r11-20261103` / `86155fbf3b89` | R34 被拒绝的取消 reserve 实验；归档，不恢复旧执行准入上限。 |
| #101 | `feature/wsp-semantic-certificate-20261106-r1` / `77ddf7eb82b1` | `feature/wsp-native-semantic-replay-20261105-628b` / `f9c121fa54c4` | semantic continuation certificate 与 cohort 和当前 runtime 主动整合。 |
| #104 | `experiment/x230-r35-observation-alloc-20261106` / `b6dfca7e504f` | `perf/x230-r11-20261103` / `86155fbf3b89` | R35 被拒绝的观察分配实验；源变体与拒绝证据归档。 |
| #105 | `experiment/x230-r24-phase-cost-20261106` / `8eb1a0af7a85` | `perf/x230-r11-20261103` / `86155fbf3b89` | R24 D1 非默认诊断，历史通过 D2 保留；诊断源码归档。 |
| #106 | `perf/x230-r36-20261106` / `5f048a9209a1` | `perf/x230-r11-20261103` / `86155fbf3b89` | R36 被拒绝的 audit-cache 实验；源变体与拒绝证据归档。 |
| #107 | `experiment/x230-r24-validation-cost-20261106` / `092cc578faec` | `experiment/x230-r24-phase-cost-20261106` / `8eb1a0af7a85` | R24 D2 非默认诊断；源码和诊断证据归档，不替代当前 runtime。 |
| #109 | `feat/hia-agent-native-mcp-20261106` / `9f60a30530f4` | `feature/rea-runtime-unified-20261103` / `02c390876d46` | 既有 Rust/Python HIA MCP 适配器已在冻结基线中；不属于新原生重写。 |

其中七项属于经 `77ddf7eb82b1956e5376d770b11efe0ed127f12d` 主动整合的 WSP 谱系，两项已在冻结 Rust 基线，八项是保留历史但不启用的拒绝实验或诊断变体。归档合并不改变其原有拒绝/采用结论。`additional-rust-pr-coverage.json` 保存完整 SHA、原始 review decision 和 archive manifest 对照。

## PR 关闭与分支删除是两个集合

关闭候选为 **93 个 Rust PR**：原搜索观察到的 76 个，加完整 REST 找回的 17 个。分支删除候选为 **149 个原始 Rust refs 加我们拥有的 consolidate ref，共 150 个**；只有 PR #125 真正合并、远端 main 保留全部原始祖先、默认分支切换完成并重新验证逐 ref SHA 租约后才能执行。

**旧 Rust PR #120 是必须分离处理的情况。** 它的 head 是 `codex/hia-archive-source-retention-20261111-f9aa`。PR 本身可在整合后关闭，但 head ref 是 HIA PR #121 的冻结 base，必须保留。禁止从关闭 PR 的 head 清单反推删除集合。

HIA PR #121、#122、#124 及其 head/base 依赖全部保留；六个 HIA 相关 refs 均不进入删除集合。#125 必须完成合并，不能以直接关闭代替合并。

## 期间发生的 HIA 外部推进

以下三个受保护 refs 在会话期间由外部推进：

| 保留 ref | 原始观察 SHA | 当前观察 SHA |
| --- | --- | --- |
| `codex/hia-request-context-20261114-7c666` | `64a0c9587f9bf6feed64e188c481402b2b16d998` | `0c8343eb872345d7eb7ef2538f3ed2d0b966d39b` |
| `codex/hia-runtime-native-20261114-bd947b55` | `ddab6e5c35444a4987d9e2bcc037f1ac895a2954` | `4b906c5a718a661e4fb95d1c6f0f75412ab5e012` |
| `codex/hia-shell-lifecycle-20261115-194042` | `b67ba64602a18a2c8743fe33821c3f96f1f6f725` | `0037718c94b8e8c452058cdcf781a261ac3bf09e` |

这些 SHA 是采样记录，不是复位目标。任何进一步的外部推进都必须保留，不得把这些分支恢复到旧快照。

## 时效与执行边界

search 结果不能充当执行租约：它既漏掉 17 个旧 open Rust PR，也在候选更新后继续返回 #125 的旧 head `7f3c795b`。直接单 PR GET 已确认 head 为 `4767ddc0`。直接 REST 本身也是时点观察；真正关闭前仍须逐个读取 `/pulls/{number}`，删除前须重新读取远端 refs。

#122 的直接 REST `base.sha` 仍返回 `ddab6e5c...`，而其命名 base 分支已经观察到 `4b906c5a...`。两者均受到保护，不能把 PR 的 base SHA 当成分支修改/删除租约。

本补充说明没有执行 PR 关闭、分支删除、默认分支切换或部署，也不新增任何 runtime 验证结论。候选工作树和提交保持不动。
