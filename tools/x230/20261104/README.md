# X230 R16–R18：工具与证据读者指南

本目录对应 [R16–R18 优化报告](../../../docs/X230_OPTIMIZATION_20261104_R16_R18.md)。总报告解释取舍；这里说明证据身份、文件布局和离线复算方法。

> 最终状态：采用 R18——R14 加 jobctl 缓冲读取单文件；R16 与整套 R17 的性能取舍不支持采用，原始证据完整保留。R18 第一次资格因错误复用 R17 test artifact 被独立 gate 拒绝；使用全新空 target 的第二次资格、35 项独立接受检查和最终六机恢复全部通过。17 个证据包已全部生成、传回并完成 SHA256、Git blob 及归档成员校验。九个正式 campaign 包各通过一次本地重定位审计，完整分析对象及分析文件 SHA256 与原记录全部一致。

## 1. 先辨认被测对象

| 对象 | 身份和结论 |
|---|---|
| R14 baseline | 源码基于 `a784b92df7c84e6047343b436222716eb4b532d6`；runtime SHA256 为 `51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d` |
| R16 source candidate | 路径预解析及 pin-set 缓冲复用；runtime SHA256 为 `230c71e9b0f00d9ff0f018341485f0d8f00a8a1e046b20822fa56890e7085f66`；资格通过，但整链收益不足，未采用 |
| Worker 配置与 C32 | 使用同一 R14 baseline binary，arena1；配置比较是 workers2 对 workers1 / workers4，C32 使用 workers2。这些不是 R17 上的配置穷举或 R17 的 C32 实测 |
| R17 source candidate | R14 加 jobctl 有界 `BufReader` 及延后构造 legacy 请求 JSON，不含 R16 profile 改动；runtime SHA256 为 `1c1d79911ce039186ca40817524a1f5f6b03dae4dd936ee87c0ab05b69f3cbe1`；完整资格和最终正确性检查通过，但整套源码不采用 |
| R18 最终选择 | R14 加 jobctl 缓冲读取单文件，恢复 R14 的 `jobs.rs`；资格 attempt01 已失效，空 target attempt02 及独立接受检查通过。runtime / driver 与 R14 逐字节相同，helper 与 R17 逐字节相同；恢复原审计及一次本地归档审计均通过 |
| 共同拓扑 | 固定历史 profile 的六个组：`ai395`、`mac`、`main`、`pocket4`、`rog`、`x230`；`main` 是 Linux `qian-qi`，与 Darwin `mac` 不同。拓扑 SHA256 为 `8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287` |

本轮测量选定并建议使用 workers2、arena1，常态 observation 并发优先 C8；这不表示已修改生产服务的默认环境。配置依据及其有限样本取舍见总报告；不能把目录日期或 A/B 标签单独当作 binary 身份。

## 2. 固定归档名与解包路径

每个归档 stem 对应三个文件：`<stem>.tar.gz`、`<stem>.manifest.json` 和 `<stem>.archive.json`。下表的“发布目录”相对于本 README。全部 17 包、51 个三件套文件已到货并校验，包含被拒绝的资格和未采纳的候选，未删去失败证据。

| 发布目录 / stem | 解包后的主要路径 | 实验状态与用途 |
|---|---|---|
| `r16/native-observation-01` | `r16/native-observation-01/` | 已完成；R14 对 R16，C1/4/8/16，192 measured +24 warmup/cell；保留异常长调用 |
| `r16/native-observation-02` | `r16/native-observation-02/` | 已完成；唯一确认组，C8/16，384 measured +24 warmup/cell；不与第一次合并统计 |
| `r16/workers2-vs1-01` | `r16/workers2-vs1-01/` | 已完成；同 R14 binary，C1/8/16，96 measured +24 warmup/cell，ABBA |
| `r16/workers2-vs4-01` | `r16/workers2-vs4-01/` | 已完成；同 R14 binary、相同设计，与 2-vs-1 独立分析 |
| `r16/native-boundary-01` | `r16/native-boundary-01/` | 已完成；两次 C32 burst、精确错误分类、drain 后 C1/C8 及正常重启 |
| `r16/cancel-recovery-01` | `r16/cancel-recovery-01/` | 已完成；R16 candidate 的六个真实新作业、same-key、取消、自有 controller 中断和 ROG 私有 SSH 中断 |
| `r16/qualification-01` | `r16/qualification-01/`、`r16/qualification-tools/` | 已完成；1,644 passed、35 ignored；保留命令、原始日志与原审计，不含 ELF |
| `r16/diagnostics` | `r16/diagnostics/` 及 `r16/` 下指定 review/binding 文件 | 已完成的机制实验、未采纳尝试、三次独立 review、控制 campaign 与初始 SSH 失败证据 |
| `r17/candidate-source-evidence` | `r17/candidate-source/`、`r17/patches/`、`r17/review/` 及来源映射 | R17 的两份原始候选源码副本及组合 patch，作为未采纳候选完整保留；不替换为 R18 源码 |
| `r17/qualification-01` | `r17/qualification-01/`、`r17/qualification-tools/` | 已完成完整资格；不含 ELF |
| `r17/native-observation-01` | `r17/native-observation-01/` | 已完成；同 workers2、arena1，C1/8/16，96 measured +24 warmup/cell，ABBA；正确性通过但性能不支持采用 |
| `r17/cancel-recovery-01` | `r17/cancel-recovery-01/` | 已完成；六机真实 start/same-key/cancel、controller 与 ROG 私有 SSH 中断恢复，独立审计通过 |
| `r17/final-campaign-01` | `r17/final-campaign-01/`、`r17/final-measurement-selection.json`、`r17/final-control/` | 已完成的 R17 selection/资格 gate/阶段日志、launcher 与独立最终 review；`final` 是原 R17 campaign 名称，不表示 R17 最终被采用 |
| `r18/qualification-01-rejected` | `r18/qualification-01/`、`r18/independent-invalidation-01.json` | 原阶段 exit 0 但 artifact gate 拒绝；完整保存失效资格及反证 |
| `r18/qualification-02` | `r18/qualification-02/`、`r18/independent-acceptance-02.json` | 使用全新空 target 的有效资格；1,637 passed、33 ignored，独立接受检查 35/35 通过 |
| `r18/source-decision` | `r18/` 下 source/decision metadata、`r18/recovery-control-01/`、`r18/final-adoption.json` | 最终源码身份、采用决定、恢复控制阶段及其日志 |
| `r18/cancel-recovery-01` | `r18/cancel-recovery-01/`、`r18/measurement-tools/` | 最终 R18 产物的六机真实 start/same-key/cancel 与中断恢复；原审计与一次本地重定位复核均通过 |

Native/config/boundary/recovery 每包都携带同前缀的 `measurement-tools/`，包含冻结的 12 个标准库 Python 文件。配置包另含 `configuration-tools/`，边界包另含 `boundary-tools/`。保持这些文件原字节；原 report、freeze 与 publication manifest 提供工具身份绑定，config/boundary 审计还直接核对完整冻结工具集，native/recovery 检查 allocator helper 的身份。

R17 native/recovery 的 X230 原始目录实际位于 R16 根下的 `r17-native-observation-01/` 和 `r17-cancel-recovery-01/`，以满足冻结 recovery harness 的输出约束。归档将其放到表中的 `r17/...`。这只是归档成员路径映射，不会替换原 report 中的绝对路径或改写其字节。

R18 recovery 的原始目录同样位于 R16 根的 `r18-cancel-recovery-01/`，归档映射为 `r18/cancel-recovery-01/`；R18 资格和 source/decision 仍来源于独立 R18 根目录。

Mac foreground agent 的现有旁证位于 `r16/mac-agent-evidence/`；该目录的 `manifest.json` 绑定原始报告及转发 stdout/stderr。它是控制链旁证，不替代 X230 上的逐帧证据。R17 的 selection、qualification gate、四阶段 argv/logs/退出码与最终独立 review 在 `final-campaign-01` 包中按表中布局保留。

## 3. 归档完整性与重定位

归档内的第一个成员是 `_publication/<package-id>/manifest.json`，与同目录外部 `<stem>.manifest.json` 逐字节相同。每个原始文件均有长度和 SHA256；manifest 自己不对自己做循环哈希，其精确字节的 SHA256 由 `<stem>.archive.json` 记录。

Manifest 的 `roots`、每项 `source_root` / `source_relative` 与 `archive_path` 组成路径映射。不要用 `sed` 改写原 report、规范化 JSONL、重排 JSON、删除空 stderr 或修正历史绝对路径。即使解析后的对象相同，改写也会改变证据字节。

[packaging-plan-v7.json](packaging-plan-v7.json) 列出最终 17 包；各归档仍绑定它实际打包时的 plan SHA，先前版本完整保留。`publication-attempts/attempt-01/` 与 `publication-attempts/history/` 保留第一次打包的原失败日志及工具版本；后续仅修正 inventory schema 和所需文件清单，没有因此重跑性能或资格实验。打包失败与实验失败分开记录。

离线审计使用 `--report` 定位解包后的 report，并按该文件的父目录查找 raw 文件；config/boundary 还用 `--harness-root` 指向同一解包树里的冻结工具。它们不需要恢复 `/home/qian/...`，不读取活跃 registry，不连接 SSH，也不启动 HeptaRuntime。归档校验仅证明文件完整性；它不等于重新执行实验，也不重验未收录的 ELF 本体。

### 校验后再解包

以下命令仅在对应三件套实际发布后执行。使用 Python 3.11 或更高版本与 POSIX 环境；仅需标准库。包校验工具的发布位置为本目录的 `package_x230_evidence.py`。将 `REPO_ROOT` 换成仓库的绝对路径。

```bash
set -e
REPO_ROOT=/absolute/path/to/hepta-runtime
X230_EVIDENCE="$REPO_ROOT/tools/x230/20261104"
X230_EXTRACTED="$(mktemp -d)"
X230_RECHECKS="$(mktemp -d)"

python3 -B "$X230_EVIDENCE/package_x230_evidence.py" verify \
  --archive "$X230_EVIDENCE/r16/native-observation-01.tar.gz" \
  --manifest "$X230_EVIDENCE/r16/native-observation-01.manifest.json"

tar -xzf "$X230_EVIDENCE/r16/native-observation-01.tar.gz" \
  -C "$X230_EXTRACTED"
```

只有 `verify` 返回成功才执行解包；其输出的 archive/manifest SHA256 应与 `.archive.json` 对应字段一致。其余包按表中目录和 stem 逐个校验、解包到同一 `X230_EXTRACTED`。同前缀共享工具文件必须具有相同字节；也可以为每包创建单独解包目录。

下列输出写入独立的 `X230_RECHECKS`，不覆盖归档证据。审计器使用排他创建，若输出文件已存在就选择新的目录或文件名。

## 4. Native observation 离线复算

下面两条命令分别要求相应 native 包已解开。**入口是 `analyze_native_observation.py`**；`audit_native_evidence.py` 是其逐帧、时钟和资源审计 helper，没有独立 CLI，不应直接运行后把 exit 0 当作检查通过。

```bash
python3 -B "$X230_EXTRACTED/r16/measurement-tools/analyze_native_observation.py" \
  --report "$X230_EXTRACTED/r16/native-observation-01/report.json" \
  --output "$X230_RECHECKS/r16-native-observation-01.json"

python3 -B "$X230_EXTRACTED/r16/measurement-tools/analyze_native_observation.py" \
  --report "$X230_EXTRACTED/r16/native-observation-02/report.json" \
  --output "$X230_RECHECKS/r16-native-observation-02.json"
```

它们重新检查 ABBA 顺序、每组主机/操作分布、原 job 身份、全部 response frames、初始化与重启、allocator 证明、计时端点、controller ticks 和资源 trace，再计算各 arm/C 的指标。每个 campaign 单独产生结果，与其原 `independent-summary.json` 比较；“证据验证成功”不等于“候选性能更好”。R16 两份 report 均保留，未采纳的结论不影响证据完整性。

## 5. Worker 配置与 C32 离线复算

```bash
python3 -B "$X230_EXTRACTED/r16/configuration-tools/verify_worker_configuration.py" \
  --report "$X230_EXTRACTED/r16/workers2-vs1-01/report.json" \
  --harness-root "$X230_EXTRACTED/r16/measurement-tools" \
  --output "$X230_RECHECKS/workers2-vs1-01.json"

python3 -B "$X230_EXTRACTED/r16/configuration-tools/verify_worker_configuration.py" \
  --report "$X230_EXTRACTED/r16/workers2-vs4-01/report.json" \
  --harness-root "$X230_EXTRACTED/r16/measurement-tools" \
  --output "$X230_RECHECKS/workers2-vs4-01.json"

python3 -B "$X230_EXTRACTED/r16/boundary-tools/audit_native_boundary.py" \
  --report "$X230_EXTRACTED/r16/native-boundary-01/report.json" \
  --harness-root "$X230_EXTRACTED/r16/measurement-tools" \
  --output "$X230_RECHECKS/native-boundary-01.json"
```

配置审计从每个 first/restart controller 的 `worker-environment.json` 和 NUL 分隔的 `worker-environment.bin` 复核 PID/start-ticks 与实际配置，不仅相信 argv 或报告标签。`.bin` 只包含选定的 `TOKIO_WORKER_THREADS`、`MALLOC_ARENA_MAX` 两项，不是可执行文件或完整进程环境。

C32 审计从每帧精确 envelope 分类成功、已证明的 capacity rejection 和其他错误；未知错误使诊断失败。当前两轮各 16 成功、16 精确拒绝、0 unknown，96 次 post-drain C1/C8 请求及正常重启通过。成功吞吐不包含拒绝。32 个 pending 客户端请求不等于观测到 32 个 native pool identities；内部 admission 峰值未遥测，每轮各类只有 16 个样本。

两组配置原审计名为 `independent-configuration-analysis.json`，C32 原审计名为 `independent-summary.json`。从三者原始材料再独立复算的记录位于 diagnostics 包解出的 `r16/independent-configuration-boundary-review-01.json`，SHA256 为 `94baed92429ceed2b9ef5635177f86af1c15d5df546901e68da1ec0564041bc0`。

## 6. 真实取消与恢复离线审计

```bash
python3 -B "$X230_EXTRACTED/r16/measurement-tools/verify_cancel_recovery.py" \
  --report "$X230_EXTRACTED/r16/cancel-recovery-01/report.json" \
  --output "$X230_RECHECKS/r16-cancel-recovery-01.json"
```

该命令只读已有证据，不重新启动或取消作业。它复核六个真实 start、12 次 same-key lookup、12 次 cancel、execution count、终态输出、witness、原注册记录、绑定自有 controller/ROG SSH 中断，以及独立 SSH checks。R16 原始记录包含 90 次 native 调用、36 次 SSH checks、93 个 RPC frames、72 份 SSH stdout/stderr。

这些结果不证明主机掉电、整机重启、WAN partition、所有权迁移或任意外部副作用的 exactly-once。Mac cancellation 的 account/PID-start 绑定仍是 best effort；ACK 与独立终态确认分开检查。

## 7. 原始文件必须保留哪些

| Campaign | 核心原始材料 |
|---|---|
| Native / worker 配置 | `report.json`、`topology.json`；`round-0-A/`、`round-1-B/`、`round-2-B/`、`round-3-A/` 的 `first/`、`restart/`；每阶段的 `transport-responses.jsonl`、`transport-responses.index.jsonl`、`resource-samples.jsonl` |
| Worker 配置额外材料 | 八个阶段各自的 `worker-environment.json`、`worker-environment.bin`；相邻 configuration tools 与 `harness-freeze.json` |
| C32 | 顶层 report/topology/capacity policy；`controller/first/`、`controller/restart/` 的三类 raw 文件；`controller/state/jobs/` 中由 report 的 `six_originals` 精确绑定的六份记录；相邻 boundary tools 与原 policy |
| Recovery | report/topology、六份 `<host>-request.json`、全部 `native-<seq>-<host>-<tool>.json`、全部 `ssh-<seq>-<host>-<mode>.stdout/.stderr`；`first-controller/`、`after-crash-controller/`、`after-cancel-controller/` 的 transport/index/resource 文件 |

序号使用实际文件中的零填充格式；manifest 和原 report 的长度/SHA256 是准确成员清单，不应根据裸 glob 增补其他用户的 registry。空 stdout/stderr 也是证据。JSONL transport 保留完整原始行字节，index 绑定 offset、length 和 SHA256。

Runtime profile、SSH 配置、密钥、agent socket、完整进程环境、mutable target cache 和 ELF 不收录；不需要它们即可完成以上 posthoc native/config/boundary/recovery 审计。

## 8. Qualification 与机制诊断的复核范围

Qualification 包保留原 `report.json`、isolated audit、commands/tests 索引、source manifest、构建产物 metadata 和实际测试 gzip stdout/stderr。归档校验会核对这些字节及 gzip 日志绑定。ELF 和完整 retained test artifacts 未收录，因此不能声称在任意解包目录直接重跑原 isolated auditor 就完成了资格重验；原工具可能需要原 artifact/源码路径和 ELF。完整重新资格验证是另一个构建与测试任务。

资格验收还必须检查实际构建和测试 artifact 是否来自声明的源码；不能只看到原 `report.qualified=true` 就接受。R18 的第一次资格是已发现的反例：原报告和成功日志完整保留，但独立 artifact gate 将其判为失效，详见第 11 节。

针对缓存事故范围，已对两个历史资格包做一次只读元数据核查，记录在 [qualification-freshness-review-01.json](qualification-freshness-review-01.json)，SHA256 为 `30348299e6ea7094e588eb55cda9435ae4e8275db3a3310766eeb8f10ebc2830`。R16、R17 的 `cargo-no-run.jsonl` 各自第 305 行都是唯一根库 `hepta_runtime` libtest 的 `compiler-artifact`，两者均为 `fresh=false`；其原 test-build 用时分别为 1,021.613 s 和 771.039 s，stdout SHA 与对应 Cargo 文件相同。R17 使用 R16 target 目录，但该根库产物仍被 Cargo 明确标为重新编译。

保留测试索引与原审计记录的 R16 根库测试 SHA 为 `9f545bb4122ae997dee0d69736b89c740a11f8dddc7a32caa975203cb0f2e589`，R17 为 `5394e8bcf30258e24ea3fa7975c1b9c8f2ec00c613bf58f5299cddd627f0c288`；各自原 before/after 相同，两候选不同。侧证绑定原 Cargo 行、保留路径映射及所读成员的完整 SHA。这里只核对归档中的元数据和原 binary hash 记录，没有在本地重验未收录的 ELF，也不声称所有依赖都重新构建。

Diagnostics 包保留未采用候选和失败尝试。`profile-microbench-test-profile-01` 的 runner 误选同名 CLI artifact，运行了零个目标测试；`...-02` 修正后执行了目标测试。初始两个 SSH preflight 缺少所需 identities，第三次才成功。它们不能从记录中删除，也不能改写为源码或资格失败。

jobctl 的机制材料位于 `r16/diagnostics/jobctl-buffer-probe-01/`，实际 raw 在 `attempt-01/`。单独复算 ABBA timing 汇总：

```bash
python3 -B "$X230_EXTRACTED/r16/diagnostics/jobctl-buffer-review/summarize_microbench.py" \
  "$X230_EXTRACTED/r16/diagnostics/jobctl-buffer-probe-01/attempt-01/timing.jsonl" \
  "$X230_RECHECKS/jobctl-buffer-summary.json"
```

这条命令不会编译或执行 probe；它检查已记录的四个完整 ABBA blocks 并重算 timing 汇总，不替代 raw `verify.jsonl`、`oracle.jsonl`、`verification-summary.json` 或完整资格。使用普通 `python3`，不要加 `-O` 禁用原 summarizer 的断言。

jobctl 使用一份 release probe binary 和合成文件，测试真实复制函数的组件行为；不包含真实 sudo、systemctl、SSH、全局控制锁或生产 helper 部署。Read oracle 是单独未计时的调用计数，不是 strace 系统调用实测。合法 JSON fixture 的消费字节相同；提前解析失败时缓冲可能预取更多字节，但内部 `Take(INPUT_MAX + 1)` 保留物理读取上限。不能将 85%–99% 的局部 CPU 改善写成六机 MCP 吞吐改善。

## 9. 如何读指标

- Native throughput 是冻结已完成作业的 `process_status` / `process_read` 成功调用数除以 cell 墙钟时间，不是新作业启动或集群计算吞吐。Warmup、preflight、restart 检查不进入性能分母。
- 同一 campaign、同一 arm/C 的两个 cell 按总调用数、总时间计算 rate 与 CPU/call；p95/p99 从其全部原始 latency 计算 nearest-rank。ABBA 两个配对分别是 B1/A0、B2/A3。每臂两个 controller，不能据此声称统计显著或绝对最优。
- CPU/call 来自同一 PID/start-ticks 的 `/proc` utime+stime 前后差，计数区间包围整个 cell。它含 controller 全部线程，按系统 ticks 量化，不是逐 RPC 的精确 CPU 归因；Python harness 与远端 CPU 不在其中。
- VmHWM 是 first controller 生命周期内观测到的高水位，包含 preflight、warmup 和全部并发 cells，不是某个 C 的 steady-state RSS。SSH/子进程资源来自 100 ms 非原子采样，可能遗漏短命进程或重复计算共享页，tree CPU 窗口差不是严格下界。
- 清理结果只覆盖绑定或已观测的本轮自有进程及记录。缺失采样和分类未知保留在 trace，不能将其当成零资源或证明整个集群不存在泄漏。
- C32 的拒绝延迟、拒绝 rate 与成功分开；CPU/attempt 包含成功和拒绝，不能直接与正常 C8 的 CPU/success 比成优化。
- R16 两次源码实验、两个 worker 实验以及 jobctl 机制实验各自保留；不跨 campaign 池化、删除异常值或改变成功分母来制造收益。

## 10. R17 历史最终验收与未采纳结论

R17 完整资格与四阶段控制 campaign 已通过。资格绑定 `source_tested == source_after == implementation-ready.source_inputs`；最终使用 workers2、arena1。Native 为 1,152 measured +288 warmup +72 preflight/restart，共 1,512 次成功调用、0 failed、1,520 个 raw RPC frames。Recovery 为 90 次 native 调用、36 次独立 SSH checks、93 个 RPC frames 和 72 份 SSH streams，六个新作业各执行一次。所有已观测自有进程 survivor 列表为空；四阶段退出码均为 0、stderr 均为空。

额外的唯一一次 posthoc review 重新运行冻结 native/recovery 原始数据审计器，所得完整对象与两份原 `independent-summary.json` 逐字段一致；同时复核 control stage logs、产物、selection 和资格身份。它没有启动 HeptaRuntime 或重复 benchmark。

| 并发 | A calls/s | B calls/s | A CPU ms/call | B CPU ms/call | A p99 ms | B p99 ms |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 4.279382 | 4.217508 | 128.1250 | 127.2396 | 426.0606 | 410.8917 |
| 8 | 23.277448 | 23.087624 | 72.7083 | 71.7708 | 480.4512 | 566.7200 |
| 16 | 23.380438 | 23.138828 | 72.9167 | 74.2188 | 820.4803 | 932.1350 |

A 为 R14，B 为 R17。C16 两个配对的吞吐变化为 −0.942% /−1.125%，CPU/call 为 +2.571% /+1.000%，p95 为 +2.733% /+3.293%，p99 为 +15.208% /+15.221%。C8 CPU 略降，但吞吐两对均下降，p99 配对 +14.074% /−4.611%，方向不一致。First controller 观测 VmHWM 均值只减少 20 KiB，两个配对方向也不一致。所有异常值保留；最长 measured 调用为 983.491 ms，没有删除失败或长调用改善分母。

这些取舍不足以采纳整套 R17；有限 ABBA 不证明某一源码改动因果导致回归。jobctl 的机制证据仍独立成立，转入 R18 单文件候选。保留全部 R17 原始 `final-*` 字段和文件名，不将未采纳候选改名成 R18。

最终两包已实际生成、传回并通过一次本地重定位审计。对应离线命令为：

```bash
python3 -B "$X230_EXTRACTED/r17/measurement-tools/analyze_native_observation.py" \
  --report "$X230_EXTRACTED/r17/native-observation-01/report.json" \
  --output "$X230_RECHECKS/r17-native-observation-01.json"

python3 -B "$X230_EXTRACTED/r17/measurement-tools/verify_cancel_recovery.py" \
  --report "$X230_EXTRACTED/r17/cancel-recovery-01/report.json" \
  --output "$X230_RECHECKS/r17-cancel-recovery-01.json"
```

下表是已经完成并归档的原始文件身份；路径是固定归档映射。Native/recovery 在远端位于 R16 根的 `r17-*` 目录，report 本身没有改写。

| 解包后路径 | SHA256 |
|---|---|
| `r17/qualification-01/report.json` | `883d65c6947f6d6617dabc9af04246fb28e75b4fdb473e175a65212d5e14f1a9` |
| `r17/final-measurement-selection.json` | `bc3e8e9e38b2efdf9257a777951022bc4b6416725497977db5d78d8bcb7a7ebf` |
| `r17/final-campaign-01/report.json` | `8bc8450b7a9916312ebeb0aa713ba4fc40225be99be0f20520ec470b433cf0b7` |
| `r17/native-observation-01/report.json` | `c61510a186c9eb7a3d0f6e7e2db2e3f327936bffa7486ffd40b8dd4316e499f3` |
| `r17/native-observation-01/independent-summary.json` | `ed0b27c2191614abf686646d47e5cbee7350cc3b82fa53006773b0730e3c1482` |
| `r17/cancel-recovery-01/report.json` | `5c6f46f5dd48915e61b69f3ba89944c5bdbfe8de2c4e55a5011d2d4448d8b04a` |
| `r17/cancel-recovery-01/independent-summary.json` | `40a2ce40437fb3f8ddc3cdcef914244616ef12e2e32c38e2f388351bf2b58bab` |
| `r17/final-control/r17-final-independent-review-01.json` | `6a462fcf70100a962227cc3762b6d95b746a7e89f69d954c6f941ccb7e2988da` |

## 11. R18 最终资格、采用与证据复用

R18 从 R14 原始 281 文件 /219 编译输入重新固定源码，仅加入已验证机制的 jobctl 缓冲读取，恢复 R14 的 `jobs.rs`。独立资格不借用 R17 的 `qualified=true`；最终只采用这一个生产源码文件的变化。

**第一次资格无效，不能作为 R18 的通过证据。** 源码准备使用 `copy2` 保留了旧 mtime，Cargo 共享缓存把 R17 的 libtest 当成 `fresh=true` 复用；实际 artifact SHA 已由独立 gate 证实。虽然 `qualification-01` 的原阶段退出码均为 0，原 report 也写了 `qualified=true`，这只说明那些命令成功执行，不证明测到的是声明的 R18 源码。原报告、原日志和独立 invalidation 必须一起保留，不回写原报告掩盖这一失败。

原始失效说明为 `r18/independent-invalidation-01.json`，SHA256 为 `fe2e17894b1d73ab8eeae4e35f7c678adccfc818793974151cfed6e643299727`，随 `qualification-01-rejected` 包保留。该包仍使用原始的 `r18/qualification-01/` 路径；`rejected` 仅用于公开归档名，原 report 没有改写。

修正后的 `qualification-02` 使用全新、初始为空的 `target-fresh-02`，不依赖 `touch` 或继续信任原缓存。完整资格已通过：1,637 passed、0 failed、33 ignored、1,670 selected，5 个测试二进制，0 test retries。独立接受检查为 35/35 true、`accepted=true`；219 个编译输入中 218 个保持 R14，唯一 override 为 jobctl，没有新增或删除编译输入。最终 `src` Git tree 为 `8aa5705f6a42ae28938b767846b51388218b23b1`。

| 资格产物 | 实际 SHA256 | 独立逐字节比较 |
|---|---|---|
| R18 runtime | `51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d` | 与保存的 R14 runtime 相同 |
| R18 native driver | `551aa5ba0f990908d0143c34f513a0f1937f14198335c5e4a611a112b82f944e` | 与保存的 R14 driver 相同 |
| R18 jobctl helper | `61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62` | 与已资格的 R17 缓冲 helper 相同 |

这些是独立接受检查对实际产物的逐块比较，不是根据相同源码或文件名推断。按身份分别复用对应二进制的既有证据，worker、allocator、固定 profile、工具和操作分布的范围保持明确。这样复用的是同一二进制的已记录事实，不是新跑了一次 R18 ABBA，也不是 R18 的新吞吐改善。已完成的六机 operator/Python observation 仍不直接覆盖 jobctl isolated backend 的线上提速。

| 最终绑定文件 | SHA256 |
|---|---|
| `r18/qualification-02/report.json` | `e2d346eb47fce0812913cc6c830fcb945796f308c9340245b0b368b3fcc41367` |
| `r18/independent-acceptance-02.json` | `d86c5e90720e632d431af59c888910c7b186ccc62e3bf73532fe952a8f6cc219` |
| `r18/publication-source-verification-02.json` | `b238a45f538469d3b56196488d3661ed3a43d28ffca53fc3e304d43b5a324f18` |
| `r18/final-adoption.json` | `67a31950378c81340f4492b53b4906de5f2ea8081379a6ee631f211223da9e0d` |

最终六机恢复原审计已通过：90 次 native 调用、36 次独立 SSH checks、93 个响应帧、72 份 SSH streams，6 个新作业各执行一次，12 次 same-key lookup、12 次 cancel；正常恢复、绑定 controller 中断及 ROG 私有 SSH master 中断全部通过。恢复 raw report SHA256 为 `49894e6b60cee6110de391328e7c56447cf50fff03e981a3bebae4b388685ea2`，原分析为 `91b1054551fc82b1368ec14411390808f059008c19ca1336d7f5a45c354789dc`。包到货后的唯一一次本地重定位审计也已通过，完整分析对象及文件 SHA256 都与原分析相同。这份新增恢复证据不进入 ABBA 性能样本，原八包收据保持不变。

```bash
python3 -B "$X230_EXTRACTED/r18/measurement-tools/verify_cancel_recovery.py" \
  --report "$X230_EXTRACTED/r18/cancel-recovery-01/report.json" \
  --output "$X230_RECHECKS/r18-cancel-recovery-01.json"
```

三代 controller 的退出码依次为 −9、0、0；第一代为预定自有 SIGKILL，中后两代通过 stdin EOF 正常退出。三份 `observed_descendant_survivors` 均为空，`reader_error` 均为 null，`unmatched_responses` 均为 0。VmHWM/RSS 采样峰值依次为 16,056 /16,560 /15,916 KiB，controller FD 峰值均为 76；SSH descendants 的非原子 RSS 峰值为 78,868 /96,312 /95,608 KiB。退出竞态、ParentChanged 等缺失观测完整保留；这些不是全机无残留或严格总内存上界的证明。

最终资格产物保存在 X230 的 `/home/qian/hepta-runtime-optimization-20261104-r18/qualification-02/`。本次交付最终源码、已资格产物和可复算证据，没有替换生产 Mac controller、安装 privileged jobctl policy 或修改全局环境。

## 12. 已完成的本地重定位验收与正式数据总量

八个正式 campaign 包各在一个新的本地临时目录解包，先校验 archive/manifest/receipt，再与原冻结工具逐个比对 SHA256，执行第 4–6、10 节的真实 CLI 入口各一次。每份新分析的完整 JSON 对象均与包内原分析相同；原归档和 manifest 的字节保持不变。没有运行 HeptaRuntime、资格测试或额外性能负载，没有缺项失败或自动审计重试。

原八包验收记录为 [relocated-audit-01.json](relocated-audit-01.json)，SHA256 为 `778d040ee245d75ad70de03c06dc7ead68d0ac776e61aa7c5843f337eadeb7ea`。它保留每包归档身份、原命令、stdout/stderr 绑定、原/新分析 SHA256、比较结果和实际计数，新增 R18 后仍保持原字节。

| Formal dataset | Tool calls | 成功 | 预期 capacity 拒绝 | 其他 tool 错误 | Raw 响应帧 |
|---|---:|---:|---:|---:|---:|
| R16 native-observation-01 | 3,528 | 3,528 | 0 | 0 | 3,536 |
| R16 native-observation-02 | 3,336 | 3,336 | 0 | 0 | 3,344 |
| R16 workers2-vs1-01 | 1,512 | 1,512 | 0 | 0 | 1,520 |
| R16 workers2-vs4-01 | 1,512 | 1,512 | 0 | 0 | 1,520 |
| R16 native-boundary-01 | 202 | 170 | 32 | 0 | 204 |
| R16 cancel-recovery-01 | 90 | 90 | 0 | 0 | 93 |
| R17 native-observation-01 | 1,512 | 1,512 | 0 | 0 | 1,520 |
| R17 cancel-recovery-01 | 90 | 90 | 0 | 0 | 93 |
| **本次八包合计** | **11,782** | **11,750** | **32** | **0** | **11,830** |

五个 ABBA datasets 共 9,600 measured、1,440 warmup 和 360 preflight/restart calls。两次 recovery 合计 180 native calls、72 次独立 SSH checks、144 份 SSH stdout/stderr，涉及 12 个真实新作业、24 次 same-key lookup 和 24 次 cancel。响应帧比 tool calls 多 48 帧，非 tool 响应不混入调用分母。

R18 的增量验收记录为 [relocated-audit-02.json](relocated-audit-02.json)，SHA256 为 `85edaa52ccb29229f0e18ed78281ff2bf800e330c76d8f617572c66ac9e578b5`。它只执行一次新增 recovery 的离线审计，绑定原八包 receipt 的 SHA，保存三代 controller 的实际退出、空 survivor 和资源缺项，并从实际计数重算九组总量。

| 范围 | Tool calls | 成功 | 预期 capacity 拒绝 | 其他 tool 错误 | Raw 响应帧 |
|---|---:|---:|---:|---:|---:|
| 原八包 | 11,782 | 11,750 | 32 | 0 | 11,830 |
| 新增 R18 cancel-recovery-01 | 90 | 90 | 0 | 0 | 93 |
| **最终九包合计** | **11,872** | **11,840** | **32** | **0** | **11,923** |

三次 recovery 合计 270 native calls、108 次独立 SSH checks、216 份 SSH streams、18 个真实新作业、36 次 same-key lookup、36 次 cancel。九组共有 51 个非 tool 响应帧。五组 ABBA 的 measured/warmup/preflight 计数不变，R18 没有新增或重跑吞吐 ABBA。

这些是从已到货且实际复算的九个包相加得到的计数，不是合并性能样本或新的吞吐指标；资格、机制实验、初始 SSH preflight、打包及操作性工具调用不在 formal dataset 合计中。两份本地收据没有重跑原实验或资格，没有缺项失败或自动审计重试。

## 13. 发布总索引

本指南冻结后，由主控生成 [publication-manifest.json](publication-manifest.json)，绑定 stage 内全部实际叶文件，包括最终 `src/bin/jobctl.rs`、主报告、本 README、Mac 控制旁证、各 tar/外部 manifest/receipt 和发布工具。文件清单以实际内容为准，不把计划产物算成已交付文件。

总 manifest 排除自身，避免循环哈希；提交的 Git tree 绑定 manifest 本身。归档内部 manifest、外部 archive receipt、总 publication manifest 和 Git tree 各自承担明确的一层字节身份，不改写历史 report 的原路径、原状态或原哈希。
