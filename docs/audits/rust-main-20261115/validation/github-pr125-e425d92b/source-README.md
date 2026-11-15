# PR #125 最终候选 e425d92b：托管 CI 已通过

两个适用 workflow、三个 job 均为 `completed / success`，59 个 job step 全部成功。证据仅绑定以下本轮源码，不把之前候选的失败或取消改写为通过。

| 对象 | 精确标识 |
| --- | --- |
| PR | [#125](https://github.com/TrillionniumFoundation/hepta-runtime/pull/125) |
| Candidate head | `e425d92b6a0dedf13eb3e484e76419ee756804c0` |
| Candidate tree | `76652098f4b5bcad487071f2eaefd82d7fed219c` |
| GitHub prospective merge | `a5f07cba04e7a592a78a7a9adcd2b10666ab2055` |
| Base main | `ba574f2a6a1b74e85191c58d7bec011720736bb9` |
| Rust PR run | [43701857912](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43701857912) |
| Cloud PR run | [43701857874](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43701857874) |

Rust exact-head job `132774532555` 明确检出 candidate head，prospective-merge job `132774532810` 明确检出上表 merge SHA；Cloud job `132774532159` 也明确检出 candidate head。实际 checkout 与身份校验行在完整日志中保留。Cloud push 的 paths 只覆盖 `tools/cloud-compute/**` 和其 workflow，本次 test/audit 更新未触及这些路径，因此本轮没有另一个适用 Cloud push run，也未制造变更触发重复检查。

## 实际测试结果

| Job | 全特性 Rust nextest | 无默认特性 Rust nextest | Python unittest |
| --- | --- | --- | --- |
| Exact head | 2633 通过，0 失败，44 跳过 | 2592 通过，0 失败，32 跳过 | 937 次运行：936 通过，1 跳过 |
| Prospective merge | 2633 通过，0 失败，44 跳过 | 2592 通过，0 失败，32 跳过 | 869 次运行：869 通过，0 跳过 |
| Cloud PR | 不适用 | 不适用 | 191 次运行：191 通过，0 跳过 |

Cloud 的 191 项由 Router 46、Colab 69、Kaggle 76 组成，之前修复的 lease 竞争回归有明确 `ok` 输出。完整 Rust 套件相对上一轮增加了 3 项 transport framing 测试；旧的 EOF 失败记录仍单独保留。

这些是**每个特性模式、每条验证线的执行次数**，不能称为不重复的测试数。两条线、两个模式合计 Rust 通过执行 10450 次。三个 job 的 Python `Ran` 合计 1997 次，其中 1996 通过、1 跳过；`unittest` 的 `Ran` 包括跳过，nextest 的 `tests run` 不包括另列的 skipped。非 unittest 的 CLI、发布二进制烟测与产物门禁单独记录，不混入 Python 用例数。`*-counts.json` 保留对应原日志行号与时间，`derive-job-counts.py` 提供只读计数过程。

Rust 跳过数来自实际 nextest 汇总。`declared-ignored-tests.json` 只是固定源码中 44 个 `#[ignore]` 属性的静态清单，不是执行名单；其中部分私有 worker 由父测试显式调用，手动基准或真实主机/oracle 验证不能因为默认套件通过而被算作已运行。

## 其他完成的门禁与运行时间

两条 Rust 验证线均完成固定 Rust 1.95、格式检查、两种特性模式的 all-target check 和严格 Clippy、固定 nextest 0.9.137 的完整测试、相关 Python 回归、release build，以及真实 JavaScript MCP worker 的取消、回收和后续请求恢复。nextest 保留 `--test-threads 1 --retries 0 --no-fail-fast`；没有增加重试或削减测试。

Exact head 还通过 unbounded ingress/collector 回归、release 二进制解析器及 Linux syscall-denial 烟测、独立 Python ZIP writer 到所构建 Rust worker 的静态验证。Exact head 的 28 个 step、prospective merge 的 24 个 step、Cloud 的 7 个 step 全部成功。

两个 Rust job 各保留 150 分钟预算。实际 exact head 从 `09:59:35Z` 到 `11:31:42Z`，为 92 分 7 秒；prospective merge 从 `09:59:37Z` 到 `11:22:20Z`，为 82 分 43 秒。完整 Rust run 于 `2026-11-15T11:31:43Z` 更新为成功，没有 timeout、取消或资源故障的最终结果。上述 job 总耗时包含工具安装、编译和其他门禁，不等同于 nextest 汇总的纯测试执行时间。

## 本地环境限制的托管复测

`environment-retests.json` 保留对应真实日志行。先前本地 `/proc` owned-child 检查、Landlock 限制和 10 项 X230 Unix socket 相关错误，在两条托管验证线中都有相同测试名的明确 `ok`。Exact head 的 HTTP bridge 四项整组通过；修复单复数断言后的 recovery control-channel 33 项在两条线中均通过。后两组使用非 verbose 输出，因此只声明整组结果，不虚构个别用例日志。

本轮唯一 Python 跳过来自 `tests/search_worker_tests.py`：17 次运行，16 通过，1 跳过。CI 非 verbose 日志没有打印原因；固定源码仅有一个 `skipTest` 分支，在导入 `pypdf.PdfWriter` 发生 `ImportError` 时使用“optional pypdf parser unavailable in this interpreter”。因此将其归为可选 PDF parser 不可用，是结合唯一源码分支作出的推断，跳过项未算通过。

之前本地完整 Clippy 的 SIGKILL 原始日志仍保留；本轮两种模式、两条验证线的严格 Clippy 全部成功。托管通过不能反推本地信号退出一定由 OOM 引起。

## 完整日志和产物

三个 `.log` 均为对应 job 的完整原始文本，未删改早先输出。`final-runs.json`、`final-jobs.json` 是最终 API 快照，`initial-state.json` 和 `observation-timeline.json` 保留观察过程，`summary.json` 提供最终机器可读结果。

`artifacts/` 保存 GitHub 返回的三个原始 ZIP 和只读检查收据，三个 ZIP 的 SHA-256 均与 GitHub API digest 相同。下载使用的临时签名 URL 未存入证据。

| 产物 | GitHub artifact ID | 原始 ZIP SHA-256 |
| --- | --- | --- |
| Merge JavaScript cancellation | `14159865268` | `aaa7dd49afd237f593d71e879ab54529873a4b209d0e070127b166a38b664be8` |
| Exact JavaScript cancellation | `14159507710` | `2b206e8812d1db2513c1f6d3ff5e4a6c38c9b211297f1c387a8b55e623a666f8` |
| Exact independent ZIP smoke | `14159826672` | `2dec4bd2a0d44252b434a0e80f9018956254afeffdb3296d4952c69eca52236d` |

两个 JavaScript `qualification.json` 都是 `qualified=true`，四项 worker/取消/原 owner 回收/后续恢复门禁均为真，源码字节未变；没有由 harness 手动 SIGKILL worker，原 owner 在关闭前已经回收 worker。两个 release binary 的观察 SHA-256 相同：`383003b04bb85110a7322115acd90d21882a1f497af5917584acc07bfc9639ad`，均为 24092928 bytes。

ZIP smoke 验证结构预览和预期拒绝，包括 CRC 字段不一致、重复条目、截断和 signing-block 结构错误；它不证明 APK 密码学签名、签名者身份或 Android 语义。产物名称因 workflow 使用事件 merge SHA 而包含 `a5f07cba`，包括 exact-head 产物；源码身份应看 job checkout、run head 和收据，不能只看产物名字。

`manifest.json` 对本目录除自身外的所有文件记录字节数与 SHA-256。绝对路径均为实际执行环境证据，不是用户路径。此次观察只读取 GitHub 状态、日志和产物；没有重跑/取消、真实外部主机访问、生产部署、发布、真实云任务或 HIA 操作。CI 的 release build 是构建验证，不表示对外发布。
