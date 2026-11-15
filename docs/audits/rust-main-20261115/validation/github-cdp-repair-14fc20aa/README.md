# Chrome CDP 清理修复：真实 push 验收通过

**新 head `14fc20aabd0650784664fc9659f53936430622df` 的 Chrome workflow 成功，真实 CDP 观测与进程清理均完成。** 原 `737acf6f` 的失败证据保持原样；本次是修复提交触发的新 main push，不是重跑或改写原失败。

| 标识 | 值 |
| --- | --- |
| Head | `14fc20aabd0650784664fc9659f53936430622df` |
| Tree | `9d4585566a22cd192a76c745b758ccfec153864a` |
| Parent | `737acf6f901e46c57b0b4374e323e0d1132e0d49` |
| Workflow | `405194661`，REA P4 real Chrome CDP observation reference |
| Run | [43715911837](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43715911837)，`push / main` |
| Job | `132817283097`，`completed / success` |
| 运行时间 | `2026-11-15T12:50:49Z`—`12:51:38Z`，49 秒 |

## 实际测试和浏览器结果

Job 的 **9 个 step 全部成功**。临时浏览器生命周期回归 **8/8 通过，0 失败、0 跳过**；完整日志记录 `Ran 8 tests in 1.878s` 和每个用例的明确 `ok`。

八项覆盖取消、父进程先退出且子进程逃离 session、dead snapshot 后出现新 orphan、保留 probe 失败、probe 失败优先于清理失败、清理失败使原成功 probe 失败、TERM 协作退出，以及线程组 leader 为 zombie 但 writer 仍活着的情况。负向 fixture 中的注入错误和 37/143 等退出码是所验证的预期结果，不是托管 job 失败；各 fixture 都有 PASS 及对应 cleanup receipt，完整保存在日志和 `validation.json`。

实际运行 Node `v24.22.1`、Chrome `157.0.8103.50`，保存的真实 CDP 观测仍满足原五项断言：provider 正确、页面 text/title 正确、navigation frame ID 存在，且 `productionAdapterQualified=false`。测试仍只证明本次临时 loopback 页面上的 CDP 观测，不扩展成 production adapter 资格。

## 真实清理收据

原始 artifact 中的 `process-cleanup.json` 明确记录：

| 字段 | 实际值 |
| --- | --- |
| `probe_exit_status` | `0` |
| `cleanup_exit_status` | `0` |
| `final_exit_status` | `0` |
| `lifecycle_error` / `cleanup_error` | `null` / `null` |
| `remaining_live_children` | `[]` |
| `profile_removed` | `true` |
| `term_used` | `true` |
| `escalated_to_kill` | `false` |
| Owned sessions | 3 |
| 唯一已回收 PID | 18，包含全部 3 个 session leader |

上述字段来自本次托管 owner 的真实收据，不是本观察者事后对 runner `/proc` 的独立读取。本轮有界 TERM 清理已完成，无需升级 KILL；profile 删除成功，旧的 EXIT-trap `Directory not empty` 故障没有再出现。

## 源码身份与未弱化的原断言

GitHub commit 元数据确认该提交仅更改两个 CI Python 文件和一个 workflow；Rust 源码、Cargo manifest 和 Cargo.lock 没有变化。下载的三份源码计算 Git blob SHA 后，均与该 commit 的对应 blob 完全一致。

| 源码 | SHA-256 |
| --- | --- |
| `.github/scripts/rea_browser_session.py` | `196b63ffd0b5d721dd62061608f53946054480c894dfb203482a0bfc6e06cbd1` |
| `.github/scripts/test_rea_browser_session.py` | `a06db8b25a1781707d3687e034550b130a14132c17063ae6d86ffeaeac862a85` |
| `.github/workflows/rea-browser-real.yml` | `102364f8e9af438c2e7f607c89846101c485a2cc14166294b6686d8231cd0cb3` |

与封存的失败源码比较，原内联 JavaScript 和五项 Python assertion block 的实际代码字节均未改变。JavaScript SHA-256 为 `8667a7cdffa74b316344519016fea30436dc5de28192bf9c660d32961eeacb74`，assertion block 为 `d1308dec2862964adbfb84adb589b7754dd4aaa01c8001e0174c70995ed567b7`；本轮 artifact 内 `cdp-test.mjs` 也逐字节匹配。

## 证据完整性与范围

原始 artifact `14162920802`，6011 bytes，SHA-256：

`eb4b6ae452fb2d80ca78031703f617c58424a5ce15efca895121a64d1d9fb75b`

该 SHA 与 GitHub API digest 相同，ZIP CRC 验证通过。目录保留完整 job 日志、全部 steps/run metadata、原始 ZIP、产物逐成员 hash 与只读收据、源码副本、commit metadata、按 case 的验证记录，以及 `manifest.json`。下载临时签名 URL 没有写入证据；没有执行下载的产物。

generic repository `actions/runs?head_sha=...` 查询完整返回 3 个 run，第二页为空。其中 Chrome 已成功；初次读取时另外的 Rust push `43715911808` 和 dynamic CodeQL `43715911688` 仍运行中。本报告不将这两项标为成功，也没有等待、重跑、取消或 dispatch 它们。此次检查只针对专门 CI 生命周期修复和真实 Chrome 验收，不重复完整 Rust 构建。

所有观测仅 GitHub GET 和 artifact 下载，加本地证据只读验证；没有 runtime host calls、仓库/配置修改或远端 mutation。旧失败与已封存 e425 CI 目录均未修改。
