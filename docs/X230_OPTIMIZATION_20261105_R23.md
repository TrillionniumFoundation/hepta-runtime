# X230 R23：性能改善，但连接中断恢复失败，保留 R22

**R23 不采用，生产源码仍保持已接受的 R22。** 本轮完整资格通过，六机观测 C8 吞吐较实际 R22 基线提高 **18.263%**、controller CPU/call 降低 **31.896%**，最大采样 controller RSS 增加 **480 KiB**；性能与资源门均满足。但同一 campaign 的取消/恢复阶段在主动中断 ROG 的私有 SSH master 后失败，整体 `passed=false`、`adoption_passed=false`。性能改善不能覆盖这项正确性失败。

## 候选与资格

基线为实际已发布 R22 源码提交 `afec5354d1e0eca09f10ccabd73a01be2f14092c`，对应 runtime SHA256 `346b57590211e62ce8732dfcea703c2fae4b2dca5fd62f870c1abd34b1158d20`。后续 R22 证据提交没有修改 src 树。

R23 将 R22 的完整文件参考比较扩到固定 `/usr/bin/false` 和固定系统 shell。SSH、false、shell 按原顺序共享一个每 Profile 2 MiB 参考字节预算，未放进预算的文件仍走原 SHA 路径；被拒文件不消耗预算。每次验证仍完整 fresh read，保留原元数据、路径、取消、deadline 和 owner/await 边界。三个公共文件合计参考字节为 1,003,608 B，较 R22 多 156,720 B。该预算不等于进程 RSS 上限。

八个资格阶段均退出 0：format、fmt-check、harness-tests、严格 all-targets/all-features Clippy、test-build、isolated-tests、独立测试审计和 release。五个测试目标合计 **1,679 selected、1,645 passed、0 failed、34 ignored、0 retries**。实际 220 项编译输入在测试前后相同，完整文件与 Git 基线绑定仅有三个源码/测试文件变化，候选 src 树为 `a9fd3be3e13b1bf6440037d51106d3579b9570aa`。

本次从 R22 复制未修改的依赖缓存后重编根 crate，没有宣称全空 target 构建。候选 runtime 为 14,372,488 B，SHA256 `265c17bff3cd774f0aa4a8b96043437bee5e240e244cb07deabfcb69db78169b`；jobctl 和 native driver 与 A 完全同 SHA。候选 patch 单独留证，没有应用到分支的生产源码。

## 已完成的六机观测和容量测量

负载是已完成作业的 `process_status` / `process_read` 观测 RPC，不能解读为新作业启动或集群计算吞吐。使用固定六物理机器拓扑、workers=2、arena1；90 秒编译后冷却，C1/C8/C16 按 ABBA，各 cell 192 measured + 24 warmup。实际 **2,304 measured + 288 warmup + 72 preflight/restart = 2,664 tool calls，0 failed**，原始独立审计通过。

| 并发 | R22 calls/s | R23 calls/s | 吞吐变化 | Controller CPU ms/call：A → B | CPU 变化 |
|---|---:|---:|---:|---:|---:|
| C1 | 7.8508 | 7.7743 | −0.98% | 39.3750 → 29.4531 | −25.20% |
| C8 | 46.4662 | 54.9524 | +18.26% | 28.9844 → 19.7396 | −31.90% |
| C16 | 44.7403 | 58.2249 | +30.14% | 29.1406 → 20.4948 | −29.67% |

| 并发 | p95 ms：A → B | p95 变化 | p99 ms：A → B | p99 变化 |
|---|---:|---:|---:|---:|
| C1 | 186.932 → 186.692 | −0.13% | 223.200 → 212.076 | −4.98% |
| C8 | 225.350 → 206.517 | −8.36% | 262.625 → 235.805 | −10.21% |
| C16 | 437.587 → 329.829 | −24.63% | 487.152 → 359.419 | −26.22% |

冻结门为所有档位 throughput B/A ≥0.95、p95 B/A ≤1.10；C8 另需 throughput ≥1.03、CPU/call ≤0.97。最大采样 controller RSS 为 A=18,864 KiB、B=19,344 KiB，增加 480 KiB，低于 min(A+512 KiB,A×1.05)=19,376 KiB。四个 controller/arm（含 restart）的原采样均保留。RSS 是采样峰值；CPU 仅计 controller，不包含 harness 与远端作业。有限 campaign 不构成置信区间。

C32 两次 burst 合计 **32 success、32 精确 capacity rejection、0 other error**，202 个 tool calls，排空和恢复的独立容量审计通过。拒绝不计成功吞吐；这不证明 32 个内部成功 admission，也不证明固定最大并发。

## 阻断采用的真实失败

取消/恢复阶段创建了六个新的有界私有作业。原 harness 对已确认身份的 ROG SSH master 发送 SIGKILL，并用 pidfd 确认原进程已终止。随后的首个 ROG `process_status` 返回 `isError=true`，原文为 **`observation SSH child exited`**。该调用耗时 62.558515 ms；原始 reply 为 118 B，SHA256 `a7c3191f69a47b43af3bee7b3517ee8213262b5bd88677d37d4ef1433688760a`。

本阶段实际执行 29 次 native calls、17 次独立 SSH calls；只有上述 native call 失败。停止时尚未执行 controller crash/restart、same-key lookup 或 cancel，故这些项目不能宣称通过。stage 返回 1，launcher 正常记录失败并停止，没有性能或 RPC 自动重试，没有生成全链成功 summary。

源码核对显示 R22/R23 的 `ssh_observation_pool.rs` 完全同字节，SHA256 `018828a4f686aff1692e6f3fb09846ed22714239252149825ba25e4978612ed2`。现有请求路径先按 accepting 和剩余 AGE 取得 master lease，再调用 `verify_live`；周期维护另行发现终态并退休 master。原错误与“原 master 已终止、维护尚未退休、请求先进入”这一既有竞态一致。没有内容、SHA、stamp 或 reference 错误证据，也不能仅凭本轮时序证明参考扩展本身造成了该竞态。

失败 controller 的 EOF shutdown 退出 0，原记录 `observed_descendant_survivors=[]`；Mac 临时 agent 已回收、目录及 socket 均消失。随后独立的只读核对已取得全部六个原 fixture 的 exit/witness 与持久输出：六者都在原 210 秒 release gate 超时后自行退出，exit_code=1、cancelled=false、timed_out=false，job/nonce/原请求及 witness SHA 全部匹配。新核对没有启动 controller、创建 job、cancel、release 或重试；它验证终态发布收据，未独立探测 PID/group 活性，也不把失败 campaign 改为通过。

## 决定与后续范围

保留 R22，完整保存 R23 原失败。下一候选仅针对已定位的 admission 窗口修复：在远端 slave/命令尚未启动且原 Child 明确终态时，释放当前租约容量并进入已有的单代续建流程；身份、IO、socket、peer 等错误仍失败，不重放已提交命令。它需要自己的决定性回归测试、完整资格和新的六机对照，不以延迟 harness、增加 RPC 重试或改门槛消除失败。

详见 [R23 证据索引](../tools/x230/20261105/r23/README.md)。原资格 report SHA256 为 `c9c78be4c93d2f9246a317d27f7a616431f31157a05b8cc46d9dc1cf86c848d7`；整体失败 campaign report 为 `44b74c25cc429ccbb125b88a65778ef2030fe4fa742d17a63994f4f4ec48dfa8`；取消/恢复 report 为 `04bccf0b9a38d7188521d7ed7d0c18ff4a28a4ab571333e4e84a80b3f12d1abf`。所有已绑定输入、A/B 源码及二进制在 campaign 前后未改变。
