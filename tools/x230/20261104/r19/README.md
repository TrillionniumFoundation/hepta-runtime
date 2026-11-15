# X230 R19：证据索引与离线复核

本目录记录 R19 的原始测量、构建资格、失败尝试和独立复核。结论与适用范围见 [R19 完整报告](../../../../docs/X230_OPTIMIZATION_20261104_R19.md)；历史基线见 [R16–R18 证据说明](../README.md)。归档完成、证据校验成功、资格通过和采用候选是四种不同结果。

| 最终状态 | 实际结果 |
|---|---|
| qualification02 及独立验收 | 通过：1,637 passed / 0 failed / 33 ignored；独立验收 24/24 检查通过，jobctl 与 R18 逐字节一致。第一次 qualification01 的拒绝结果保留。 |
| 实际 R19 runtime SHA256 | `adab5f27f89b3cac6adaec916110a48d80697db9667e3bd7ee0fc713fe770a09` |
| 六机 native / recovery / C32 | 原始数据本地复算通过：native 2,664 calls /2,672 frames，C32 202 calls /204 frames，恢复 90 calls /93 frames；合计 2,956 calls =2,924 success +32 capacity rejection +0 other errors，2,969 完整响应帧。三个新分析文件 SHA256 与原件相同。 |
| 采用决定 | 本轮采用 R19 候选。依据为组件 CPU／跟踪分配改善、故障路径 descriptor 清理修复及预注册整链不回退筛选通过；未建立集群吞吐提高或稳定 RSS 下降的证据。此决定不代表已部署到常驻服务。 |
| 最终归档计划及迁移复核收据 | 十个包均已生成；本地闭包计划 `670c03c9…`、闭包收据 `deaaef84…`；83 个运输文件、九个远端包及三项原始分析全部复核通过，22 项源码绑定检查通过。详见下方最终文件链接。 |

## 1. 十个证据包各自证明什么

下表名称均为本目录内的 archive stem。每个包有 `<stem>.tar.gz`、`<stem>.manifest.json`、`<stem>.archive.json` 三件套。前九个来自关闭证据写入后的 X230 原目录，最后一个来自本地开发与复核目录。路径改为归档布局，文件内容保留原字节；报告中原来的绝对路径不会改写。

| Stem | 主要内容与用途 |
|---|---|
| `qualification-01` | 第一次完整构建和测试的原始日志、gzip 测试输出、source map、构建产物元数据、原 qualifier 和独立拒绝。**这次产物被拒绝**，不能因后续成功而改称接受。 |
| `prequalification-component-01` | 四个外层阶段的原始 stdout/stderr、X230 最终语义测试、96-cell 组件 ABBA 的 protocol/raw/summary，以及原五个启动与测试工具。外层预资格结果失败；其中独立成功的语义与组件证据通过相同源码哈希复用。 |
| `qualification-02` | 在另一个空 target 重新执行的实际第二次完整资格、原始测试输出和独立验收。保留真实 verdict，归档完整不预设接受。 |
| `qualification-resolution-02` | 原拒绝的绑定、证据复用、第二次阶段日志、三工具 manifest、source freeze、qualifier PID/start-ticks/wait/reap 与严格 jobctl 门槛的关联。 |
| `qualification-diagnostics-01` | 原环境/fingerprint 与 ELF 诊断；tiny Cargo unset/empty/unset 的源码、命令流、TypeId 输出和六份原 fingerprint JSON。没有收录 target 树、可执行文件或完整进程环境。 |
| `campaign-control-01` | 固定计划、实际 campaign02 启动器、逐阶段前后检查、原始阶段流和收尾证据。未使用的旧 campaign 启动器也保留。`01` 是第一次正式六机实验编号，不是 qualification01 的产物选择。 |
| `native-observation-01` | C1/C8/C16 的原 ABBA、预热、初始化/重启、原始 transport/frame index、CPU ticks、resource trace、原分析结果及原测量工具。 |
| `native-boundary-01` | 当前 R19 二进制的两次 C32 突发、精确 capacity 分类策略、全部原始调用与资源证据、排空和恢复检查。不是历史 worker sweep 的替代记录。 |
| `cancel-recovery-01` | 当前 R19 的六机取消与恢复、三个 controller 代际、原请求/回复、独立 SSH stdout/stderr、资源与实际关闭证据。 |
| `local-development` | 代码/补丁修订、失败与成功的语义尝试、早期中止的云端组件运行、fixture smoke、独立审阅、源码树派生记录、离线重算 helper、Mac holder 原始流，以及收到的原 X230 组件证据副本。早期云端数据不算作 X230 性能样本。 |

另外保留原始组件传输归档 `component-evidence-01.tar.gz`，SHA256 为 `4d9787b50d914d3407ce5f15465060ff5e35828b5f489528fb39cc4dbc6a8dd5`。它是原接收归档的逐字节副本，供 29 项组件离线审计检查原始传输身份，不是新增实验或上述十个包之一。若传输时使用外层 envelope，它仅压缩这些已冻结文件的运输，不修改内层归档、manifest、报告或实验编号。

## 2. 第一次拒绝、第二次资格与证据复用

qualification01 的完整测试为 1,637 passed / 0 failed / 33 ignored，但独立验收因 jobctl 二进制不等于 R18 而拒绝：R18 为 `61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62`，被拒产物为 `43a40254d5812a81d9824e30ad75c0eca6cf9ddab04e03a1afb48de102797510`。测试通过不能覆盖这项身份失败。

第一版启动器把两个 `CARGO_BUILD_RUSTC_*WRAPPER` 键设为空字符串。对应版本的 Cargo 源码表明：空 workspace-wrapper 不执行包装程序，却仍进入 workspace 编译单元的 metadata 哈希。X230 的独立 tiny ABA 同时切换两个键；unset 两次的 metadata、二进制和 TypeId 输出相同，empty 的三者不同，数值结果始终为 42。它验证构建环境能改变同源码产物身份；没有逐键隔离，也不证明完整 jobctl 语义等价。

qualification02 使用同一份冻结源码，移除四个 wrapper 环境键并在新的空 target 完整构建，继续要求 jobctl 与有效 R18 逐字节一致。最终状态以本页开头和实际 `independent-acceptance-02.json`、`qualification-resolution-02.json` 为准。第一次拒绝、原工具与原日志保留，不用复制基线二进制替代构建。

X230 成功的语义测试和组件 ABBA 未因构建环境修正而再跑一次；复用的是源码、工具与原始文件哈希均相同的证据。该复用不等于让 qualification01 的失败消失，也不把组件 CPU/分配收益当成六机整链收益。

## 3. 精确源码和工具身份

父提交为 `a83fe08d736522cf01adee53902e3c13fbc1d5ae`。R19 的 219 个编译输入相对于有效 R18 只改变 `src/mcp/runtime/jobs.rs`；full source inventory 为 281 个文件。归档中的 map/freeze 绑定完整清单，`candidate-source` 只保留选定文件内容，不能把它当作整个源码 checkout。

| 文件或产物 | SHA256 |
|---|---|
| R18 `src/mcp/runtime/jobs.rs` | `694a4e4dcbc2be499879abd837f0b5e399f9cad95caab34716907de15cbbe82f` |
| R19 `src/mcp/runtime/jobs.rs` | `c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9` |
| 两轮相同的 `src/bin/jobctl.rs` | `c22fdcd5bafad3a2123d5817c27fd73e7b5c26001bf1a8bdd6f8dbacabc8b562` |
| `Cargo.toml` | `3121870fbf66f65ce6b1925b3500eae8a05fc2d8019a2694da7d6fe941ad4d28` |
| `Cargo.lock` | `15b9fb468eb34a210238657d132cbf19e961552d1313de488e1f14936bfa4e5f` |
| `rustfmt.toml` | `bce79651b2e2ff42e1c54b9a26c5e17af5222f9f65ab51d9563a48fd159dae84` |
| 有效 R18 主 runtime | `51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d` |

`local-development/review/derived-source-proof-01/` 保留原 R18 树证明和 R19 期望输入 map。仅替换 `jobs.rs` 的 Git blob `af9960abb23fcc2d8d44dde47badc6c99c3afd8e` 后，R19 的 `src` 树为 `3aa8c9aadbf42b6a0ebdac3954bd1e64b4055e20`。这些是独立重算的源码身份，不表示任何构建或采用结果。

下表路径相对于各包解出的 `r19/`。原五工具位于 `orchestration/`，新资格工具位于 `orchestration-02/`；其原 manifest 分别为 `83ff759b13d380aa8a5e3e786b4ed68887fcce47b51d7f9e80583408e6b08a8a` 与 `b5193baae4169243b92c6ae1f26460a19f0098429fb331f4a48b1450536b726b`。

| 原工具路径 | SHA256 |
|---|---|
| `orchestration/python_read_probe.py` | `c6bd04ea22d4b368a3eed1cf17642b9418f6e2c0ebc2fc8fde26db92a42df0a8` |
| `orchestration/test_python_read_bounds.py` | `b2fcba8bf78e895f79cef2b6326b69a76c68f8f8b873b72833023cde8e1d5db1` |
| `orchestration/qualify_candidate.py` | `5ac522870dd347fd12dcb723857957918666bddcf59e440f3a1cbe330e6704ba` |
| `orchestration/verify_qualification.py` | `212b23cbdfdd24c952f6519db4b13d3036b642b8d6115f38db00306303dbb95f` |
| `orchestration/run_prequalification.py` | `99057103d5b4b3149431ebf79c294088c531b24f17dd24baee5a85598b260fd6` |
| `orchestration-02/qualify_candidate_02.py` | `1e69e4e39156ea878e14c2dd6237ff450f49def76873814ab5cb14bdba5e125f` |
| `orchestration-02/verify_qualification_02.py` | `c21607f53082021311a3639d888f7a51c0113df8d4d4014d1c95d69969aed00f` |
| `orchestration-02/run_qualification_02.py` | `91625e1f5dcff0869f1d96b6162ce167a33b7d25022500b7ae6d10dd0a5ee4fe` |
| `campaign-orchestration/run_six_host_campaign_02.py` | `73fe7f80b726c0f051de47321e1249ca9ad4cadb1cd9c795a1a9783715f69588` |
| `qualification-tools/qualify.py`，实际 X230 qualifier | `95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d` |

未使用的 `campaign-orchestration/run_six_host_campaign.py` 原 SHA256 为 `3042a23c705983db411e6b69e6dda39b00c4fba91966fcff9c53610d53fa1096`。本地 `qualification-reference/qualify.py` 多一个尾随换行，其 SHA256 为 `d6979715bf7c61d7b2d9373b9d0bd68247104dbfdfa27862fbfb1cfba9d42e7f`；它仅是保留的参考文本，不能替代上表实际执行的 qualifier。

## 4. 先校验，再解包

使用 Python 3.11 或更高版本、POSIX shell 和 `tar`；下述离线审计只用标准库，不连接六台主机、运行 runtime、重建软件或重跑性能。不要使用 `python -O`，部分原复核工具依赖断言。只有对应完整三件套确实收录后，才执行相应命令。

共享校验工具为上一级的 `package_x230_evidence.py`，SHA256 为 `226edda9684f742178398c09266a171df38df5e505c0020372e72265ff684c43`。归档首成员 `_publication/<package-id>/manifest.json` 与外部 manifest 相同；manifest 列出每个原文件的路径、字节数和 SHA256，不对自己做循环哈希。`.archive.json` 绑定归档及 manifest 的精确字节。

以下示例把每包解到各自的新目录，避免多个包共有的同名原工具互相覆盖。复算结果也写入独立目录。`R19_REPO` 应填真实绝对路径，其祖先不能含符号链接或 `.`、`..` 路径段；校验工具会拒绝这些路径。

```bash
set -e
R19_REPO=/absolute/path/to/hepta-runtime
R19_EVIDENCE="$R19_REPO/tools/x230/20261104"
R19_PACKAGES="$R19_EVIDENCE/r19"
R19_PACKAGER="$R19_EVIDENCE/package_x230_evidence.py"
R19_EXTRACTED="$(mktemp -d)"
R19_RECHECKS="$(mktemp -d)"

for R19_STEM in qualification-01 prequalification-component-01 qualification-02 \
  qualification-resolution-02 qualification-diagnostics-01 campaign-control-01 \
  native-observation-01 native-boundary-01 cancel-recovery-01 local-development
do
  python3 -B "$R19_PACKAGER" verify \
    --archive "$R19_PACKAGES/$R19_STEM.tar.gz" \
    --manifest "$R19_PACKAGES/$R19_STEM.manifest.json" \
    > "$R19_RECHECKS/$R19_STEM.archive-verify.json"
  python3 -B - "$R19_PACKAGES/$R19_STEM.archive.json" \
    "$R19_RECHECKS/$R19_STEM.archive-verify.json" <<'PY'
import json, sys
from pathlib import Path
saved, actual = [json.loads(Path(p).read_bytes()) for p in sys.argv[1:]]
assert saved['verified'] is actual['verified'] is True
for key in ('archive_bytes', 'archive_sha256', 'manifest_sha256', 'member_files'):
    assert saved[key] == actual[key], key
PY
  mkdir "$R19_EXTRACTED/$R19_STEM"
  tar -xzf "$R19_PACKAGES/$R19_STEM.tar.gz" -C "$R19_EXTRACTED/$R19_STEM"
done
```

`verify` 检查成员完整集合、长度、SHA256、规范路径和元数据，并拒绝重复、额外成员及链接。它校验已有记录的身份，不把包中的 `passed=false` 改为成功。

## 5. Native、恢复与 C32 的确定性离线复算

保留相应包的全部目录结构。原分析器会从完整 transport、frame index、时钟端点和资源 trace 重算，不只读取表格数字。下列入口 SHA256 分别为 native `cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66`、recovery `0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c`、C32 `8ad8f6d97a5bd2e4850b02cd66fa5d2ac7d237ea0eef043daf9c88d3c9c152ee`。

```bash
R19_NATIVE="$R19_EXTRACTED/native-observation-01/r19"
R19_RECOVERY="$R19_EXTRACTED/cancel-recovery-01/r19"
R19_BOUNDARY="$R19_EXTRACTED/native-boundary-01/r19"

python3 -B "$R19_NATIVE/measurement-tools/analyze_native_observation.py" \
  --report "$R19_NATIVE/native-observation-01/report.json" \
  --output "$R19_RECHECKS/native.json"

python3 -B "$R19_RECOVERY/measurement-tools/verify_cancel_recovery.py" \
  --report "$R19_RECOVERY/cancel-recovery-01/report.json" \
  --output "$R19_RECHECKS/recovery.json"

python3 -B "$R19_BOUNDARY/boundary-tools/audit_native_boundary.py" \
  --report "$R19_BOUNDARY/native-boundary-01/report.json" \
  --harness-root "$R19_BOUNDARY/measurement-tools" \
  --output "$R19_RECHECKS/boundary.json"
```

把三个新结果分别与各包原 `independent-summary.json` 比较；正式发布的迁移复核收据记录实际命令、原/新 SHA256 及比较结果。`audit_native_evidence.py` 是 native 的内部 helper，没有独立 CLI，直接运行它的 exit 0 不能视为审计通过。

Native 的 rate 是完成作业的 status/read observation 吞吐；controller CPU/call 只覆盖该 controller，不等于集群 CPU。C32 将成功、明确 capacity rejection、其他错误分开，拒绝不计成功吞吐，不要求固定 16/16 分类数量。恢复检查不扩展成主机掉电、WAN partition、owner transfer 或任意外部副作用的 exactly-once 保证。

## 6. X230 组件统计的独立重算

原 helper 为 `local-development` 包中的 `r19/local-development/review/component_recompute.py`，SHA256 为 `4253bf2a4309052506f90ceae088e39fdb930238737ea204427a724cbc2e47db`。它读取原 cells、抽取源码函数身份并复算统计，不导入 probe 执行被测函数，不启动 worker。

其 `--evidence-root` 必须同时包含原 `component-evidence.tar.gz` 和解出的 9 个证据文件加 manifest。前述包保留这 10 个解出成员；下面把单独发布的原 tar 复制为 helper 要求的原文件名。R18 baseline 源码来自既有 `r18/source-decision` 包，不能用当前 checkout 中已经修改过的 `jobs.rs` 代替。

```bash
python3 -B "$R19_PACKAGER" verify \
  --archive "$R19_EVIDENCE/r18/source-decision.tar.gz" \
  --manifest "$R19_EVIDENCE/r18/source-decision.manifest.json"
mkdir "$R19_EXTRACTED/r18-source"
tar -xzf "$R19_EVIDENCE/r18/source-decision.tar.gz" \
  -C "$R19_EXTRACTED/r18-source"

R19_LOCAL="$R19_EXTRACTED/local-development/r19/local-development"
R19_COMPONENT="$R19_LOCAL/x230-component-01"
R19_ORIGINAL_TOOLS="$R19_EXTRACTED/prequalification-component-01/r19/orchestration"
test ! -e "$R19_COMPONENT/component-evidence.tar.gz"
cp "$R19_PACKAGES/component-evidence-01.tar.gz" "$R19_COMPONENT/component-evidence.tar.gz"

python3 -B "$R19_LOCAL/review/component_recompute.py" \
  --evidence-root "$R19_COMPONENT" \
  --baseline "$R19_EXTRACTED/r18-source/r18/candidate-source/src/mcp/runtime/jobs.rs" \
  --candidate "$R19_EXTRACTED/qualification-02/r19/candidate-source/src/mcp/runtime/jobs.rs" \
  --probe "$R19_ORIGINAL_TOOLS/python_read_probe.py" \
  --tests "$R19_ORIGINAL_TOOLS/test_python_read_bounds.py" \
  --output-dir "$R19_RECHECKS/component"
```

原独立审计为 29 项通过，96 个 worker 的统计汇总 SHA256 为 `e144a0e80d6a68dbe73e835e7b007a149adf533f98b3ca31ebb5da85b64002d4`。新的审计收据含新的执行时间/路径；应比较重建的 `recomputed-summary.json` 与原 summary，而非要求两份审计收据本身相同。

CPU 百分比是四个配对 block ratio 的中位数；tracemalloc 列是各 arm 的 24 个未计时峰值样本的中位数。全部 worker 的进程 HWM 均为 23,588,864 字节，本组数据没有证明 RSS 下降。64 KiB 夹具为小 JSON 加空格；live 身份的原 boot/start 字节未留存，只能核对已有绑定和 worker 相等断言，不能声称独立重建了每次实际返回全文。descriptor 修复证明函数级关闭行为；普通远端 Python helper 退出也会由操作系统回收 descriptor。

## 7. 资格归档和离线复核的边界

两个 qualification 包保留原报告、八阶段 stdout/stderr、tests/commands 索引、gzip 原测试流、source manifest、Cargo artifact 元数据和实际 qualifier/harness 文本。**ELF、retained test executables 和整个 target 树未收录。** 因此可以复核原始结果、哈希绑定、fresh=false 等已记录事实，却不能仅凭解包目录重新完成要求实际 ELF 的独立资格检查。

不要在解包目录直接执行原 `qualify.py`、`qualify_candidate*.py`、`run_qualification_02.py` 或原独立 verifier 后，把路径缺失或启动新构建误当成“离线重验”。完整重建与重新资格是另一项有实际资源开销的工作；本页命令只复算已经保存的证据。源码树派生证明只绑定文件身份，也不替代实际构建、测试、二进制门槛或采用决定。

慢调用、失败尝试、原 qualification01 拒绝和早期云端 fixture 失败均保留。组件改善、证据完整、native 回归筛选和最终采用分别解释；不从这些有限场景宣称吞吐已达全局最优。

## 8. 本次实际发布记录

- [最终逐文件清单](publication-manifest.json)
- [远端冻结计划](r19-plan-final-02.json) 与 [本地闭包计划](r19-plan-local-final.json)
- [原始运输索引](original-transfer-index-01.json) 与 [组装还原收据](outer-restore-01.json)
- [三个原分析的本地复算收据](offline-raw-replay-01.json)
- [219 输入源码绑定](qualified-source-binding-01.json) 与 [配对及资源派生指标](derived-campaign-metrics-01.json)
- [包含失败尝试的编排观察](orchestration-observations-01.json) 与 [本地证据闭包收据](local-plan-closure-01.json)
- [最后一个包的实际打包报告](local-export-run-01/report.json)

完整 raw replay 收据 SHA256 为 `a700ef8f737bf2ceb9704930a9afc6fc9c6c57f8cc0f5953a12f9163a78ddf38`；源码绑定为 `1b8fbf0126d2f78e1c588df7812aeb8a332398cfcfb2294cea9764e72d6f18f3`。最终本地计划为 `670c03c9e809d78ab0419507943afbf50bdb6489c2930934a05223196833b357`，local-development 归档为 `551477872059dd7700e4c43722a5f116ccf9c106d94f5bafe1a811ad735ee5bc`。

本地包保留发布前的结果快照；当前 docs 报告和本页在归档身份已知后完成，未把归档哈希写回其自身。原运输封装保留于执行记录，其 7,712,102 字节与 SHA256 `6e329b2b9adffc23c06496c68efeeea07605ce1ee28079a92cc3e2d508accd93` 已在原端、Mac 副本及本地组装后共同验证。对外保留的文件清单覆盖本次源码、报告和独立三件套，不需要再复制整份外层封装才能复算。
