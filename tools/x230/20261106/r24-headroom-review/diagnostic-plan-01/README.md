# R24 阶段成本诊断：最小静态计划

状态：仅设计，未实现、未编译、未执行。此目录不是新 runtime 候选，不更改 R24 接受基线、R35 冻结源码或任何性能接受门槛。接受源码固定为 baab4def80be7af015b2e7a594cb302f66c4130e 的 R24 编译输入，完整 220 项 map SHA256 为 c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd。它不证明当前对外服务的 controller 正在运行该版本。

## 要解决的问题

先确定每次跨机观测的成本落在哪里，再决定是否值得改变结构。现有约 20 ms/call 是 controller 进程自身 CPU，不能据此推算本地 SSH 子进程、远端 Python、网络或整套系统总 CPU。R27 原组件中约 0.619 μs/call 的序列化收益与这个分母相比很小，不能用微秒级静态分配计数承诺吞吐上升；既有结论见相邻 final-02 报告。

这次计划只建立四种可区分的证据：controller 同步工作 CPU；controller 内排队和等待的墙钟时间；本地 SSH 创建与生命周期成本；远端 helper 的自身 CPU 与处理时间。无法进一步识别的区间保留为 transport/调度/网络混合等待，不命名为“纯网络耗时”。

## 既有指标已经能证明什么

原 original-benchmark.py 的 cell 在同一 controller PID/start-ticks 上读取前后 utime+stime，按实际调用数计算 controller_cpu_ms_per_call。该分母不包含子进程 CPU。单个 cell 的全部调用、失败、原始响应均需保留；不按成功过滤。

原 observation_resources.py 每 100 ms 抽样后代，以 PID/birth_ticks 与可观察亲缘分代。它明确记录短命和重新托管的子进程可能漏采、生命周期统计跨越端点、区间误差可能正负。该统计不是完整子进程账单，不能从它反推每次 SSH CPU，也不能把缺样本的零值解释为零消耗。[S7][S8]

粗略算式 55 calls/s × 20 ms/controller-call ≈ 1.1 CPU-seconds/s，仅把两个给定数字相乘；它不证明某个核、锁、网络链路或远端进程饱和。

## 最少需要的阶段边界

| 阶段 | R24 位置 | 拟收集的证据 | 必须保留的解释边界 |
|---|---|---|---|
| 原请求解析、record/binding、JSON 准备 | jobs.rs status_job/read_job；ssh.rs prepare_observation/run_job_observation | 对无 await 的同步段，记录同一 TID 的 thread CPU 与墙钟；外层另记总墙钟 | check_ref_async 的异步等待须另拆；不能把整个 future 的线程 CPU 差当本请求 CPU |
| admission、owner channel、host/global、master ready | pool capture/enqueue/admission_profile/request_budget/execute_inner | 相同 controller 单调钟上的入队、获准、owner 开始和结束事件；原 deadline、host、请求序号、master generation | 等待 wall 不等于 CPU；三个容量层与 master 更新单列，不能只给一个“SSH 时间” |
| 完整文件校验 | pool verify_files/verify_profile_for；validation Workers::run_retained | validation semaphore 等待、spawn_blocking 提交至开始、worker 同步 closure CPU/wall、owner ticket.finish 同步 CPU/wall | worker 与 owner 都保留原全量 read/hash/reopen/check_current，不以缓存或弱校验降低测量成本 |
| agent/socket/boundary | verify_profile_for；execute_inner socket/peer 检查 | agent 请求墙钟、owner 同步边界检查 CPU/wall；标注生命周期检查或逻辑请求检查 | 不把 agent 本地 Unix socket 等待叫远端网络；不记录凭据或任意 argv/env |
| SSH 参数、创建、post-exec proof | Core::arguments；Core::spawn | 参数准备与 Command::spawn 的 owner-thread CPU；spawn 调用 wall；返回至原 post-exec proof 的 wall；原 child generation | spawn wall 包含父端创建/exec 协议与调度，不等于纯 fork 或 SSH 完整 CPU；不得新增第二个 reaper |
| stdin/两个输出流/child 终态 | Core::captured | 原四个并发 future 各自开始/结束、字节数、原 child 的最终状态及真实回收 | 四段重叠；不能相加当总耗时。写完仅证明本地管道接受字节，不证明远端已读取或执行 |
| 返回后的 authority、JSON 解析、审计与响应编码 | execute_inner 最后 verify_request_profile；ssh run_job_observation；jobs observation_completion_audit | 同步解析/编码 CPU；审计 semaphore、blocking queue、AUDIT_LOCK 等待与持有、write/sync_data CPU/wall | 原每事件 fdatasync、owner/身份绑定与错误顺序不变；持锁墙钟包含 I/O 等待，不能全算 CPU |

以上是有限的阶段记录，不要求新 tracing 服务或通用遥测框架。事件只含内部序号、固定阶段枚举、host alias、原 PID/start identity、线程 identity、时长、计数字段和结局；容量固定，溢出明确使该诊断不完整。完成后写到独立 sidecar，不能把诊断文字混进 MCP/stdout/远端 JSON，不能在被测锁内同步写日志。

## 为什么先拆文件校验和审计

R24 的 observation owner 在独立 current-thread runtime 上运行。正常 warm、无 master renewal、无错误的 execute_inner 明确执行三次 verify_request_profile：初始 admission、提交前、响应后。每次 verify_profile_for 做两次 verify_files；每个 verify_files 在 blocking worker 完整读后，还在原 owner 的 ticket.finish 中完整再读。因此这一条静态成功路径为 3 × 2 × 2 = 12 次固定文件集验证。Profile 中是五个 files，加 shell target，共六个固定文件；静态为 72 次固定文件验证调用，另有 shell resolution、policy、边界、agent 等检查。[S1][S4][S5]

这不是测得的 72 次物理磁盘 I/O，也不是 CPU 归因，更不构成删除重复检查的许可。页缓存、文件大小、算法后端、实际路径、线程调度都未在本计划测量。worker 在 await 前的快照不能替代 owner 接受时的全量复核；计划只把它们分别计量。

审计另有独立 semaphore、blocking pool 与共享 AUDIT_LOCK，且成功观测返回前保留每事件 sync_data。该路径可能消耗 CPU，也可能主要等存储同步或锁；只有分开 queue、lock 和 syscall 的 CPU/wall 才能区分。[S2]

## CPU 账目和并发的规则

1. 主指标继续用原 harness 的 controller 进程 CPU 前后差，不替换旧分母。对仪器版本可另记高分辨率 CPU 计数，但需标注来源、解析方法、端点和仪器开销。
2. thread CPU 只包围不发生 await 的同步段；同一 TID/进程 generation 必须一致。跨 await 的线程可能执行别的请求，即便 current-thread runtime 没有线程迁移也会混入别的 task。主 MCP runtime 还可能迁移线程。
3. process CPU 的某阶段前后差在 C8/C16 会包含其他线程和请求，不能当该请求 CPU。C1 也仍可能有 maintenance、审计或其他后台工作，不能自动视为纯单请求。
4. CPU 总计只汇总不相交的叶子同步段；父跨度不再加一次。owner、validation worker、audit worker 分列；生命周期、后台和未归因部分明确保留。请求 wall 使用跨度/关键路径，不相加重叠 I/O 或不同请求 wall。
5. 原进程 tick 指标与 thread CPU 时钟可能粒度不同，前后读取也有包围误差。若汇总超出允许解释的差异或出现丢事件，标记不可归因，不调平数字。

## 本地 SSH 与远端 helper：分两步，避免改变子进程所有权

**第一步不触碰 sole-reaper 语义。** 收集 controller 侧 spawn、post-exec proof、管道与原 wait 的事件，足以区分父端创建开销和等待跨度。原 Tokio Child wait 返回的现有结构只有退出状态，没有导出逐 child rusage。[S1][S6] 原 100 ms sampler 仍只作不完整资源旁证；缺失的 SSH CPU 填 null，不能填零。

若这个跨度确实足够大，再单独设计精确 SSH CPU 账目。可评估同一私有 controller 在所有原 child 已回收后的内核累计已等待子进程 CPU；只有在完整 create/reap ledger 证明该区间没有其他 child、master/probe 的 CPU 没有混入或有明确分摊、跨端点 child 完整归属且原平台计数语义已核实后，才能称为该组 SSH child 的聚合成本。它仍不能从一次累计值区分 fork、exec、加密和管道工作，也不自动提供每请求值。若这些条件无法满足，精确 SSH CPU 继续不可得。进一步的 wait/rusage 或系统事件追踪需要另行审查；禁止并发 wait4 抢走原 child、改变回收顺序或要求临时放宽主机权限。

**远端 helper 也是可选第二步。** 现有 status/read helper 没有提供自身 CPU/启动边界。未来若允许诊断改动，必须为固定 PythonStatus/PythonRead 另冻诊断包：在真实 helper 的同步处理边界记录远端自身 CPU/单调时长与原 request identity，响应 JSON 字节及 EOF 协议保持；sidecar 与内容权限独立、严格有界。入口后的计数不覆盖 Python 解释器此前启动；helper 自身 CPU 也不自动包含其启动并等待的 systemctl/ps 等子进程。需要这些成本时必须另有完整账目，不作补值。记录带来的额外 CPU、I/O 与启动参数变化需在该包中披露，不能把包装器替代原 helper 的结果称为原路径实测。

SSH master、slave 和远端 helper 是不同进程，controller、Linux 远端和 Mac 远端的单调时钟不共用原点。只比较各自主机上测得的 duration。controller I/O wall 减去 remote handler wall 所得残差仍混有 SSH、本地/远端排队、启动、加密、流控、网络和调度；它不是单程网络时间。除非以后已有获准的额外边界/网络事件证据，否则报告该混合残差即可，不扩大本计划去部署网络探针。

## 若以后实施：最小封存顺序

本节是待授权/待具体实现的设计，不是可执行入口。实际 binary、host、job、trace 和结果 pins 均未产生。

1. 将诊断源码、220 项实际 map、工具链/lock/profile、被测 ELF、原 harness 与 observer 状态冻结；原 accepted R24 ELF 和全部原件保留。只比较同一基线的诊断关闭/开启，不能把它与 R35 性能对照混用。
2. 优先只做 controller 阶段记录，不等待精确 SSH/remote CPU 的扩展。按原六 host、status/read 交替和 192 calls 的 cell 形状，在 C1 固定 OFF1、ON1、ON2、OFF2，所有 warm-up/prerequisite/原 owner 收口和实际 master generation 留证。原 held-agent、编译监视与 quiet90 控制如用于这次诊断，按原实现和阈值复用；不能临时把旁路负载混入正式性能窗口。
3. 第一组完整后，如需回答并发队列/同步瓶颈，再按同一预定 OFF/ON/ON/OFF 做 C8；这是诊断第二阶段，不能挑选第一阶段较好的 cell 或重试失败。C16 不属于初始最小范围。master renewal、冷启动与 steady path 用事件标注，所有样本留存，不能事后删除“慢样本”。
4. OFF/ON 的绝对 controller CPU、wall、RSS、事件体积和差值共同报告。若仪器开销或缺失事件妨碍归因，结论是诊断证据不足；不因为数值方便而扣除一个估算开销。第一步最多 4 个 C1 cell；第二步如事前封定进入条件则再加 4 个 C8 cell。该设计的数量不改原接受 campaign 的数量或阈值。
5. 首错停止，保存原请求、原响应、所有 partial trace 和真实 cleanup 结果。ACK 不等于 terminal，child absence 不替代原 wait，未知回收不能成功；不重启同名 cell、不换 key 重新制造结果。只有真实较大阶段成本和可保持原契约的改动，才值得另开生产优化及原完整资格。

## 输出与停止条件

报告按 host/操作/并发给：原 end-to-end wall 与 controller CPU；不重叠同步 CPU 各桶；queue/agent/validation/audit wait wall；SSH spawn/proof/I/O/reap wall；精确来源可得时才给 SSH/remote CPU；未归因残差、缺失样本和仪器开销。任何结果都不承诺全 runtime 吞吐提高或 RSS 下降。

若主要可省项仍是 R27 同级微秒分配，不建议只为此重复八门资格。若成本集中在安全校验、同步持久化或 owner 契约，先寻找不削弱契约的设计；没有可信等价方案就记录剩余瓶颈。若主要成本来自每请求 slave/helper，才进入 final-02 所述持久化或批量协议的独立研究，不能直接把现有 EOF/wait 协议改成常驻循环。

## 来源

完整字节身份、Git blob 与原文件位置在 source-index.json；所有行号均指 accepted R24 原件。原报告和原件已在 r24-headroom-review/static-01、final-02 与 references 下另行发布 blobs；本计划不改其字节。

- [S1] src/mcp/runtime/ssh_observation_pool.rs：owner 177–228；capture/enqueue 296–361；verify_files/verify_profile_for 684–720；spawn/captured 859–1028；execute_inner 1422–1535。
- [S2] src/mcp/runtime/jobs.rs：prepare_audit/append_audit/observation_completion_audit 2305–2508；status_job/read_job 4421–4525。
- [S3] src/mcp/runtime/ssh.rs：prepare_observation/run_job_observation 260–374；piped transport/JSON 448–548。
- [S4] src/mcp/runtime/ssh_observation_validation.rs：Workers::run_retained、OwnerTicket::finish 和 drain。
- [S5] src/mcp/runtime/ssh_observation_profile.rs：files/shell 789–799；verify_files_checked 809–824；verify_boundaries 826–838。
- [S6] src/mcp/runtime/ssh_direct.rs：原 child/lease/pipe/wait owner；本次大 stdin 静态附录另作限定。
- [S7] final-02/reference/original-benchmark.py：cell 487–530。
- [S8] final-02/reference/observation_resources.py：INTERVAL、Resources.sample/snapshot 及原 limitations。

附录 large-stdin-static-review.md 只追踪同一 R24 源码，对实际安装版本与本次 launch_unknown 不作归因。
