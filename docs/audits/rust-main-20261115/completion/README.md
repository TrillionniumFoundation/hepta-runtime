# Rust 分支收拢最终记录

本记录汇总已完成的合并、引用清理、独立回读和追加 Chrome CI 修复；历史失败与资格限制均保留。

## 提交与验收身份

- 汇总 PR：[#125](https://github.com/TrillionniumFoundation/hepta-runtime/pull/125)
- 最终验证候选：`e425d92b6a0dedf13eb3e484e76419ee756804c0`
- 候选文件树：`76652098f4b5bcad487071f2eaefd82d7fed219c`
- 合并前 main：`ba574f2a6a1b74e85191c58d7bec011720736bb9`
- 实际 main 合并提交：`737acf6f901e46c57b0b4374e323e0d1132e0d49`
- 合并完成时间：2026-11-15 11:33:46 UTC
- 清理完成时间：2026-11-15T12:24:00.099925+00:00

最终审计记录后续仅新增/修改 `docs/audits/rust-main-20261115/` 下的证据和说明；
额外的 Chrome CDP 生命周期修复单独列出提交、文件差异与真实托管验证；Rust runtime
源码、依赖锁及其他未列出的路径保持上述已验证候选的原始 mode/type/blob。
该文档提交的发布身份由 Git 本身和汇总 PR 的最终说明记录，不将文档提交新触发、
尚未完成的 CI 记为已通过。

## 集成候选的完整 Rust / Cloud CI

| 检查 | 精确候选 | 预合并版本 |
|---|---:|---:|
| Rust all-features | 2,633 passed，44 skipped | 2,633 passed，44 skipped |
| Rust no-default-features | 2,592 passed，32 skipped | 2,592 passed，32 skipped |
| Python unittest 摘要 | 937 run，936 passed，1 skipped | 869 run，869 passed，0 skipped |
| Release 构建与各自烟测 | PASS | PASS |

Rust PR run [43701857912](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43701857912)
的两个任务均 completed/success。Cloud PR run
[43701857874](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43701857874)
另执行 Router 46、Colab 69、Kaggle 76 项，191/191 passed。
三个 job 共 59 个已报告步骤全部成功，Rust 未重试测试。
这些是不同模式、任务的执行次数，不是不重复用例数量。
Python 唯一 skip 出现在 search-worker suite；日志未直接给出原因，结合固定源码
唯一 skip 分支推断为缺少可选 pypdf，未将该项计为通过。

[完整 CI 记录](../validation/github-pr125-e425d92b/README.md)保留全部原始日志、
三个 GitHub artifact ZIP 与 digest 校验、逐步骤状态、计数脚本和环境复测依据。
/proc、Landlock、X230 Unix socket 等此前本地受限路径的对应托管测试已通过。


Cloud workflow 的 push 过滤仅匹配 cloud-compute 目录和自身工作流；最后一次候选更新
涉及传输测试与审计文档，不会触发该 push workflow。验收要求的是当前候选的 Rust PR
工作流和显式 checkout 当前候选的 Cloud PR 工作流。旧候选的 push 成功没有被用于替代。

所有计数以最终 job 的完整原始日志为准；编译、收集测试数、通过、跳过、取消和未执行
分别记录。历史失败及修复依据保持原样：首次 REA 原文顺序失败、476 中间候选的取消、
0414 的无 LF EOF 旧预期失败，均保留在对应历史验证目录。

## 分支、PR 与源码保全

默认分支已切换为 `main`。149 个原始 Rust 引用与本次临时汇总引用共 **150 个分支**
已经通过一笔带逐项旧 SHA lease 的 atomic push 删除；删除后完整远端清单为 **7 个引用**，
即 main 与下列六个 HIA／迁移依赖引用。固定 **93 个旧 Rust PR 全部关闭**，
仅 HIA PR #121、#122、#124 保持 open/draft，其 head/base 关系没有改变。
操作时 main 为上述 `737acf6f…`；后续 CI 修复与审计文档继续在 main 上提交，不创建
新的远端 Rust 分支。

149 个原始 Rust 分支头通过真实 Git 父链全部保留；没有 squash 或重写这些原始提交。
42 份历史/被替代实现的 manifest 及 5,244 个原始 blob 路径仍可逐项复核，独立
Weight-Space 研究目录的 45 个文件保持原 mode/type/blob。旧性能失败和资格 HOLD
没有因归档或合并而升级为通过。

| 保留引用 | 清理后 SHA（12:24 UTC 快照） |
|---|---|
| `codex/hia-archive-source-retention-20261111-f9aa` | `a0dcdda1991ec536d5e2d252c006a778993fa566` |
| `codex/hia-request-context-20261114-7c666` | `035288d9b4ec3482e3498953d2c2b4d4b60da20d` |
| `codex/hia-runtime-native-20261114-bd947b55` | `7c4ef433be617341107cebc23e8cda8a39e55fe3` |
| `codex/hia-shell-lifecycle-20261115-194042` | `05081156e02468633108a7d07c18c7afb71d5434` |
| `codex/hia-shell-native-20261115-194042` | `93f320a8e02b522e4bafd4a2cf346d68069ec74b` |
| `recovery/hia-bd947-20261114` | `557220f220eb9b2e6c26a5e1c51f3546059eb236` |

HIA 开发在审计期间有外部推进。最终比对使用清理前重新读取的最新 HIA SHA；
不会将它们复位到最初审计快照。12:54:53 UTC 发布前再次读取时，仍是相同七个分支；
request-context 已外部推进到 `4f4ffe3302419f931b8ce0b6ab1d1339abb3e2aa`，
lifecycle 已推进到 `e196d6eb1cb1f3e85db426467f6d2ad496298e06`，均保持其新提交。
[发布前观察](final-documentation-preflight.json)与上表的清理时快照分别保留。固定 Rust 适配器基线 `codex/hia-archive-source-retention-20261111-f9aa`
虽已被 main 覆盖，仍是 HIA PR #121 的 base 及迁移清单的来源依赖，因此保留引用。
PR #120 已关闭，其受保护 head 引用保留。HIA PR #121、#122、#124 的关系另附前后回读。

## 旧分支名的执行依赖检查

对 7,007 个当前 tracked 文本/脚本文件检查了 149 个原分支名字面量及 URL 编码形式；
没有发现活跃安装、更新、clone/fetch/checkout/download 默认值依赖将被删除的分支。
主 CI 已支持 main，operator-parity 仍可按显式 workflow_dispatch 运行并 checkout 提交 SHA。

两个历史行为需要保留说明：branch-only runner diagnostic 在其诊断分支删除后不再触发；
ROG SMU A/B 硬件 qualification 的 branch guard 与 shell 断言仍固定旧 ops 分支，
删除该分支后从 main 手动 dispatch 会跳过该历史硬件 job。本次没有放宽其保护或
把旧硬件/生产资格转移给 main。这属于清理后的已知行为，不是新 CI 失败。
详见 [旧分支执行依赖检查](active-branch-reference-review-e425.json)。这一结论只描述清理后的
触发条件，不证明 push-delete 事件必然跳过硬件步骤。该历史工作流含有 `always()`
恢复步骤；删除事件的 ref 行为不足以作为硬件隔离保证，因此本次另行采取临时暂停措施。

## 操作与证据

完整闭环证据分别保存在 [93 项 PR 关闭记录](pr-closure/README.md)、
[引用清理与独立回读](cleanup/README.md)以及合并/来源保全收据中。
实际执行的 17 个记录全部逐字节下载并验 SHA；独立后验执行 14 次 GET，
两份完整引用清单均为七个引用，完整 PR 清单按 25／25／25／25／9 覆盖 109 项，
确认 93 个旧 PR closed、三个 HIA PR open/draft、全部原关系不变。

最初两次只读 cleanup 预检因历史 PR 列表读取超时/失败而停止，均未修改默认分支或引用。
第三次采用完整 open PR 单页检查：要求少于 100 条且全部 open，满页或异常数据拒绝，
其余执行器逻辑逐字节不变；19 项原安全 fixture、六组边界和独立审查通过。
实际原子 dry-run 成功，前后全部 157 个引用符合计划，才授权正式执行；
固定 93 项关闭由独立完整清单和逐项记录继续证明，没有被这项查询替代。

仅历史 ROG SMU A/B workflow `372929360` 的设置被临时从 active 改为
disabled_manually；GET 确认时间为 12:05:43.654792 UTC。删除和核验完成后，
恢复原 active 并于 12:26:01.790828 UTC 读回确认。原 workflow 文件和 guard 未变，
没有取消既有任务。完整 12:05:40–12:26:40 UTC 工作流窗口仅三项，ROG 新 run 为 0；
删除开始及以后的新 run 为 0。两项属于 HIA 外部推进，另一项是删除开始前的
Dependabot Graph Update。该窗口不把先前 main push 的成功或失败归因于删除。

旧 PR 关闭的第一版在首个只读 GET 解包时遇到连接器的通用提示字符串，立即停止，
尚无 PR before、close intent、outcome 或实际关闭。旧 STOP journal 原样保留。
修复仅调整结构化返回值的解析优先级以及固定 v2 路径/hash；17 项 caller 与
13 项 decoder 回归、实际只读 API 返回验证和独立审查均通过。Root 对绑定 hash 的
v2 另行授权，固定 93 项身份、逐项持久化和遇不确定结果停止的保护未改变。
第一次 Mac 只读准备检查的调用回执超时；随后使用同一幂等 key 找回原任务的
成功终态，明确 reused=true、retried_launch=false，没有重复执行或远端仓库修改。

分支删除使用一笔 Git atomic push，对 150 个具体目标逐项提供 exact lease。
默认分支的 GitHub PATCH、PR 状态及保留引用不能与 Git 删除事务共同原子提交；
因此执行器在变更前后分别重新读取并保存快照，遇到变化即停止，不自动重试、回滚
或改写 HIA。没有读取或导出认证凭据。

## 已修复问题和兼容性变化

主审计报告保留 HTTP 全入口认证与 loopback 要求、物理路径授权、远端 cwd/PTY、
原子 CREATE、CI action 固定和 ruzstd 补丁来源补全等问题的代码依据。
依赖锁仅更新七个 package 记录；固定 RustSec 数据库复扫为 0 漏洞、0 warning、
ignore 为空，360 个 registry 版本的校验和及撤回状态逐项通过。它们不构成所有未来
公告或整个生产环境的安全证明。

rmcp 3.9 的有界 STDIO reader 要求每条 JSON 消息以 LF 终止，不再交付旧版接受的
无 LF EOF 尾帧。项目保留 SDK 原有分帧行为及默认 16 MiB 行边界，REA 的独立
10 MiB 捕获边界也保持。外部 STDIO 客户端需要终止每条消息。
当前 CI 可达客户端的 60 个 Python 入口和 95 个对应源文件已只读检查，未发现
依赖旧尾帧行为的发送路径；这不推断所有外部客户端都已适配。

## 合并后额外 Chrome CDP 工作流

main 合并后额外触发的 Chrome CDP run [43709528201](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43709528201)
确实失败。原始完整日志显示 EXIT trap 删除 profile 时出现 `Directory not empty`；
保存的真实 CDP 观测已满足原五项断言。原清理代码从历史提交 `14a5b75d` 起没有变化，
main 触发暴露了这一既有 CI 生命周期缺口；失败早于本次分支删除，不能归因于删除。
具体残留 writer 在该次运行中没有进程树证据，未把推测写成实测。见
[原始失败证据](../validation/github-main-737acf6f-cdp/README.md)。

修复提交 [`14fc20aa`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/14fc20aabd0650784664fc9659f53936430622df)
只改变三个 CI 文件：浏览器 workflow、专用 owner 和回归。原 CDP JavaScript 及五项
断言逐字节保留。新 owner 为 HTTP/Chrome/probe 分别建立 session，保留未 reap 的
leader 身份，通过 subreaper 收养后代，以内核 wait 状态判断整个进程退出，并完成
有界 TERM/KILL、reap 后才删除 profile。它覆盖迟到的收养，以及 leader 显示 Z 但
其他线程仍写入的边界；保留原 probe 非零状态，并严格报告 lifecycle/cleanup 失败。

[本地修复记录](../validation/cdp-lifecycle-repair/README.md)保存最终 8/8 真实进程回归。
本地 procfs 缺少 task/children，实际验证 PPID 过滤的 stat 兼容路径；原始受阻尝试也
另行保留，不能混写成通过。独立静态审查与源码、日志 hash 绑定通过。

对应真实 Chrome push run [43715911837](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43715911837)
在该精确提交完成 success；job `132817283097` 的九个步骤全部成功。
托管回归为 8/8、0 skipped，耗时 1.878 秒。真实 Chrome/Node 与原五项 CDP 断言通过；
cleanup 产物记录 probe、cleanup、final 退出码均为 0，无 lifecycle/cleanup error，
三个本次 session、18 个唯一 PID 已 reap，live children 为空，profile 已删除，
本次真实浏览器清理仅需 TERM、未升级 KILL。它仍明确报告 productionAdapterQualified=false。
完整来源、日志、artifact 和 digest 见
[真实 Chrome 修复验证](../validation/github-cdp-repair-14fc20aa/README.md)。

[发布及源码差异核验](../publication/cdp-lifecycle-repair/runtime-source-unchanged.json)确认
除这三个 CI 文件外，所有路径、mode 和 blob 与 e425 完全相同，Cargo.lock SHA 不变，
新的 native HIA 重写目录没有进入 main。后续新触发的 Rust/CodeQL 或仅文档 CI 不能
预先记为成功；本次不重复运行未改变的 Rust 源码来代替此专项真实浏览器验收。

## 仍然有效的限制

- 旧本地 view/editor 仍有路径检查到 I/O 的竞态；远端配置根的祖先目录需要可信稳定。
- 无并发数量上限保留为现有策略，未声称通过 0.25 CPU / 2 GiB hostile-envelope 验收。
- 共享操作员 token 没有提供独立 ChatGPT 调用者隔离。
- REA 的 229 个冻结工具仍为 187 absent、23 partial、19 related，0 qualified、229 OPEN；
  37 个 native interface 的清单一致性不是完整兼容性证明。
- 旧 SFTP 为首次连接信任，不能描述为预置主机密钥或 CA/principal 证书验证。
- Python 环境未实现全部传递依赖带 hash 的封闭重现；runner image 也是重现性边界。
- macOS controller 上 durable process 的幂等查找会完整扫描历史 job 记录，可能带来
  随历史数量增长的响应延迟；本次观察到的 MCP 超时尚未定位到确定代码阶段。
  文件独立读回确认准备步骤已完成后，后续新操作使用独立的 operator PTY 身份执行，
  没有用新 key 重放不确定的旧操作。详见保留的静态源码分析。
- 生产切换、真实 SSH 负向实验、原始会话移交、吞吐及独立 Final-use authority 的原有 HOLD 保持。

本次操作范围为源码审计、Rust 历史整合、GitHub 分支/PR 清理、单一历史工作流的临时暂停与恢复，
以及证据发布；没有部署或重启运行主机。
