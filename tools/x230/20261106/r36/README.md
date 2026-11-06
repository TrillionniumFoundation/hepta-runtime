# R36 工具与证据：拒绝采纳，保留 R24

**R36 REJECTED。继续保留已接受的 R24。** R36 完整资格、外部 Rust CI，以及源码 PR 的 exact-head／prospective-merge CI 通过；六机 observation 通过非退化门限，但必选正常 C6 lifecycle 失败。总体 operation 吞吐下降 5.3884%；launch 吞吐下降 11.2386%、p95 增加 23.1775%，Controller CPU 0.12 s 超过 0.11 s 上限。异步 read 补充与 saturation 均未执行。[完整中文报告](../../../../docs/X230_OPTIMIZATION_20261106_R36.md)

候选源码提交为 `d3590733f6c301a91cb8f4fcc54ee5c3251a9530`，分支 `perf/x230-r36-20261106`，草稿 [PR #106](https://github.com/TrillionniumFoundation/hepta-runtime/pull/106)。保留源码和原始失败证据不表示采用该候选或替换生产服务。已接受性能基线 R24 为 `baab4def80be7af015b2e7a594cb302f66c4130e`。

## 实际执行状态

| 阶段 | 原始结果与边界 |
| --- | --- |
| X230 完整资格 | 八阶段退出 0；1,645 passed、0 failed、34 ignored、0 retries |
| X230 外部 Rust CI | 六阶段通过；nextest 原始输出确认 1,645 PASS、0 failed、34 ignored、0 retries |
| 源码 PR CI | 运行 42200291494；exact-head job 127833605232 与 prospective-merge job 127833605008 均 completed／success；只对应源码阶段 |
| Observation ABBA | C1／C8／C16 原门限通过；C8 吞吐 −2.2104%，C16 +0.4372%，配对方向不稳，没有稳定加速结论 |
| Normal lifecycle ABBA | 必选四项失败；内层／外层报告均 passed=false，外层 adoption_passed=false |
| Async read 补充 | **未执行**；只保留已封存协议、工具和准备记录 |
| Saturation／饱和取消 | **未执行**；不声称最大并发或饱和取消能力 |

原性能结果在 [performance/observation-summary.json](performance/observation-summary.json)、[performance/lifecycle-gates.json](performance/lifecycle-gates.json) 和 [performance/lifecycle-parent.json](performance/lifecycle-parent.json)。[Observation](reviews/observation-review.md) 与 [lifecycle](reviews/lifecycle-review.md) 独立复核各自声明了复算范围；没有把本地汇总审查写成全部原始 wire／资源计数的重审。历史停止边界见 [history-review.md](reviews/history-review.md)：已有编译配置、worker 与 allocator 取舍不能作为未尝试的新收益，有限矩阵也不证明全局最优。

完整归档取回后，另完成了[原始证据补审](reviews/raw-evidence/raw-evidence-review.md)：observation 的原 wire／资源分析逐字节重现，lifecycle 的原审计、44 份 phase 计量及四项失败门限重现，十二代 Controller 的原关闭回执与本地 writer 最终 trace 相符。原外层 `unknown` 仍保留，补证仅覆盖原四轮的明确代际与已观察后代。原早期 review 文件没有改写成事后范围。

## 目录

| 位置 | 内容 |
| --- | --- |
| `candidate/` | 预格式化及实际合格补丁、冻结 qualification input、实际 tested map、原 preparer、Git-to-tested-source 核对 |
| `reviews/` | 源码与格式化审查、observation／lifecycle 独立复算、历史停止边界核验 |
| `qualification/` | 原完整报告、隔离测试 summary、原 native terminal，以及从保留读取响应逐字节恢复的 preparation 报告 |
| `rust-ci/` | 原外部 Rust CI 与 materialization、另行取得的源码 PR CI 回执 |
| `performance/` | 原 observation／normal lifecycle summary、analysis、gates、round index 与父报告，保持原文件字节 |
| `control/` | 最终 R36 observation／lifecycle 控制、CI 模板、原 package manifests、派生脚本与纯审查 |
| `supplement/` | 未执行的独立 async read 工具、协议 sealer、实际生成的 held launcher 与纯审查 |
| `inputs/` | 实际封存 async 协议；输入不能充当实验结果 |
| `evidence/` | 原冻结 tools-01 及其审查；已下载原件归档和最终 export／verification 回执 |
| `evidence-tools-02/` | 实际完成 capture-02 的独立修复工具、审查和可复现 builder；不覆盖 tools-01 |
| `holder/` | 经固定仓库引用恢复的原 Mac holder |
| `replay-files.json` | 每个工具目标路径、SHA-256／大小，以及正文或字节相同的仓库来源 |

历史 manifests 和审查保留生成时的原字节与时间范围。测量前的 package manifest 仍说未执行 workload，格式化审查仍记录当时 qualification 正在运行，observation review 仍说明其后需 lifecycle；这些时间截面不改写成事后结果。完成结果以本 README、中文报告和对应原始终态交叉阅读。旧 helper 的 R25 schema／scope 字样保留；R36 已执行范围和拒绝结论以本轮外层报告为准。

## 恢复原冻结工具包

原冻结包中 17 份不变 helper 正文共 252,526 字节，通过已有仓库路径引用，避免重复存储。已在 `86155fbf3b89e5a77e2a4aadebd2128c663fe50b` 上核对工作树字节与 Git blob，再核对该 R36 package hashes；其中包括原 R29 stable archive helper 与原 Mac holder。

在完整仓库 checkout 中，指定一个新的输出目录：

```sh
python3 -B tools/x230/20261106/r36/materialize_replay.py \
  --repository /absolute/full-checkout \
  --out /absolute/new-r36-tool-packages
```

它先验证全部来源 SHA／大小，再向 `control/`、`supplement/`、`evidence/` 与 `holder/` 恢复 **75 个工具文件**并写 materialization receipt。该步骤仅恢复文件，不启动 SSH、runtime、CI 或负载。发布目录中的 `control/` 和 `evidence/` 包含去重引用，应在恢复 helper 后使用。已实际恢复并核对过原 control／supplement／evidence manifests，见 [replay-validation.json](replay-validation.json)。

恢复后的控制包保留原部署 manifest 和固定 X230 路径。按其原 README 的安装和输入绑定契约使用；原实验输出不可覆盖。19 个 qualification harness 已在 `tools/x230/20261028/` 跟踪，其固定 SHA 见 `candidate/qualification-input.json` 与原资格报告。R24 输入集合也保留于同一输入文档。

正常 observation／lifecycle 主要使用原本已有所有权移交的 batch 路径；本轮没有遥测两个修改路径的命中次数。测量差异不能直接归因于减少这次复制，相关 async 路径补充也未执行。原冻结门限仍据实际源码配对结果作出拒绝决定。既有 `--runtime-audit-group-commit` 已启用，更深的 durability／批处理设计不属于本轮已验证收益。

候选的两个生产调用点和两项已有测试扩展，由 `candidate/published-source-review.json` 将已发布提交的全部 220 个编译输入绑定到实际 tested map。预格式化 map 与 tested map 有意区分：rustfmt 只换行一个测试表达式，没有改变生产文件。

## 原件与采集边界

[holder-original-files.md](holder-original-files.md) 和 [JSON 契约](holder-original-files.json) 列出精确 holder 原文件。先取原 `report.json`，再按实际 `log_files` 采集，保留空文件和失败。Lifecycle holder 的 `remote_returncode=1`、`RemoteCampaignFailed` 不会自动生成 `holder.error.txt`；只有 Python 异常路径写出该 traceback 文件时才存在。Async holder 仅是获准的计划路径，本轮未执行，不能补造输出。

公开归档保留固定 scope 内的完整 qualification logs／测试库存／source maps／CI／原性能 JSON、RPC、资源记录和失败。ELF、mutable target、私有 profile、runtime 配置、SSH 配置／key 与 agent socket 正文按明确 metadata-only omission 处理。原 holder 的 agent 回收和 stage 的 owned process/group absent 不能替代外层仍为 `unknown` 的独立 Controller cleanup 结论。

每个归档成员须有 SHA／大小清单，压缩归档另有 SHA；导出和验证成功不代表性能通过。扫描器仅对声明的大小及三层解码范围进行 raw／JSON-string／hex／base64／gzip 检查，不宣称穷尽任意 secret 编码。详见 [evidence/README.md](evidence/README.md)。第一次 `capture-01` 因 JSON／解码扫描队列预算失败，在创建归档前退出 1，原失败回执保留。实际 `capture-02` 使用独立 `evidence-tools-02` 修复入队前重复内容去重，扫描规则、深度及大小／节点预算未改变。该次采集与下载后的本地验证已成功；工具修复不构成 workload 重试，原冻结 75 文件工具包身份不改写为后续修复版本。

## 已下载归档与实际验证命令

本地独立验证通过：9,447 个 payload 加 1 个 manifest，31 项明确 omission，44 份已观察 holder 文件；成员字节、inventory、SHA 与来源绑定一致，原始输入未变，有界 raw／decoded 扫描无发现。验证没有执行归档中的代码。性能原件的专门复算与这个传输／清单验证分开记录。

| 文件 | 字节 | SHA-256 |
| --- | ---: | --- |
| [evidence/r36-evidence-01.tar.xz](evidence/r36-evidence-01.tar.xz) | 3,961,240 | `30ff7e2dae12aa00a0048c9808610a76b17b4a37daa9de32dfab1fea06f2c9c9` |
| [evidence/export-report.json](evidence/export-report.json) | 4,989 | `a65780953c78c7cb7482f6565d84b31db4b483e87efddaf8dc353d0e7c6c7c69` |
| [evidence/archive-verification.json](evidence/archive-verification.json) | 4,314 | `190827cdfa65dedb634189616d6e0e272609acfe1ecba0e155fa33ef3892debb` |

实际 capture-02 的 verifier 是 `evidence-tools-02/verify_r36_evidence.py`；旧 `evidence/verify_r36_evidence.py` 保留为原 tools-01。使用完整检出、实际下载原件与一个全新的绝对输出路径：

```sh
python3 -B tools/x230/20261106/r36/evidence-tools-02/verify_r36_evidence.py \
  --archive /absolute/full-checkout/tools/x230/20261106/r36/evidence/r36-evidence-01.tar.xz \
  --report /absolute/full-checkout/tools/x230/20261106/r36/evidence/export-report.json \
  --report-sha256 a65780953c78c7cb7482f6565d84b31db4b483e87efddaf8dc353d0e7c6c7c69 \
  --out /absolute/new-r36-archive-verification.json
```

详见 [evidence-tools-02/README.md](evidence-tools-02/README.md)。原 tools-01、第一次失败和修复版本分别保留；不覆盖或修饰历史失败。

## 发布状态

R36 的性能决定已结束：拒绝采纳，保留 R24。源码提交 `d3590733f6c301a91cb8f4fcc54ee5c3251a9530` 的 exact-head 与 prospective-merge CI 已验证。最终证据提交的 CI 将在发布后回读实际结果并链接至 [PR #106](https://github.com/TrillionniumFoundation/hepta-runtime/pull/106)，不预填未来提交 SHA 或成功状态；后续归档与 CI 记录不会重新打开性能门限或把未执行阶段改为通过。
