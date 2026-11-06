# R24 后续优化：绝对成本预算与结构方向

**建议：两个新的局部分配候选先登记，不仅因这两项就再开完整八门资格。更值得调查的是每次观测的进程生命周期开销，但它需要新的传输协议和成本定位，不能作为小补丁直接接入。R35 继续其已经安排的原完整资格。**

本报告补充 `r24-next-hotspots-review-01` 的原代码、历史和字节证据；该第一版原件保持不变。全程只读本地/Git 和做静态计算，没有 runtime patch、Rust/Cargo/rustfmt、fixture、benchmark 或 x230/Mac API 调用。

## 微优化能回收多少 CPU

原 R27 的普通 Python status/read 等权组件平均节省 **0.61852976 μs/call**，对应从平均 13 次 allocation 降到 2 次，即少 11 次。原报告将这与历史 R24 controller CPU/call 对照，约为 **0.003201%**；R27 因绝对成本很小，没有升级到完整资格或六机接受。它不是“完整 runtime 测试失败”。

R27 组件使用相同的静态 Python command **stub**，保留一次 command String 分配，但没有执行真实 SSH、远端 helper 或运行完整命令。因此它能提供微小序列化工作的量级参照，不能测出真实 argv 的拷贝或进程启动成本。[原组件说明](history/r27-component-README.md)

本轮优先项 `ssh_observation_pool.rs::Core::arguments`（R24 **735–828**）有 30 对固定选项、60 次临时非空 `to_owned`，随后才格式化为返回的 argv。若极粗略地把 R27 全部节省按删除的 allocation 数线性外推，`60 / 11 × 0.61853 ≈ 3.37 μs/call`。这只是**预算模型，不是测量、可信上限或 allocator 单价**：数据结构、编译器、字节数和分配器争用均不同。它支持“先按微秒级看待”，不支持“吞吐会明显提高”。

以父任务给出的约 **20,000 μs controller CPU/call** 作便于判断的近似分母：

| 假设实际节省 | 可回收 controller CPU 占比 | 解释 |
| --- | ---: | --- |
| 1 μs/call | 0.005% | 小准备工作情景 |
| 3.37 μs/call | 约 0.0169% | 上述粗糙线性模型 |
| 10 μs/call | 0.05% | 比该模型更有利的情景 |
| 50 μs/call | 0.25% | 显著更有利，仍不足 1% |
| 200 μs/call | 1% | 仅作数量级参照，并非预设新门槛 |

第一项可去掉临时 owned key/value，保持最终 argv 的完整字节和顺序、返回类型及所有安全检查；没有常驻缓存。第二项是 `Core::spawn` **870–873** 为 NUL 分隔 expected argv 预留已知容量，保留完整 `Vec<u8>`、postspawn 和 argv 相等比较。第二项的原 `collect` 实际 realloc 数尚未测量，**不能给出可信点估计**；它只省潜在向量扩容，不删除 syscall 或证明流程。

没有证据认为这两项可以回收足够多的 controller CPU，使一次完整资格和原六机 ABBA 成为当前最有价值的下一步。若以后做成本很低的真实函数组件，应先报告绝对 μs/call 和 allocation/realloc，保留原样本；只有实测量级明显值得继续时，再由原流程决定是否升级。这是工作优先级建议，不修改任何已有正确性或性能门槛。

## 约 20 ms/call 究竟统计什么

已读冻结 `original-benchmark.py` **502–514**：CPU 分子是同一 controller PID/start-ticks 在 cell 前后的 `/proc/<pid>/stat` **utime + stime**，不含 `cutime/cstime`。它不包含本地 ssh 子进程或远端 Python 的 CPU。

`observation_resources.py` 的子进程树数据只是 100 ms 采样诊断，原代码明确标记可能漏短命或重挂父进程、只记录部分生命周期，并且 **不作为性能分子**。不能用采样树 CPU 或远端启动耗时直接减去这约 20 ms。[冻结计量源码](reference/original-benchmark.py) 与 [资源计量范围](reference/observation_resources.py) 保留在本包。

`55 rps × 20 ms ≈ 1.1 CPU-seconds/second` 是粗略算术关系，并不证明某一个核、某一把锁或某个阶段已饱和。C8/C16 吞吐接近也不能单独定位原因。保留三轮完整 profile/agent/socket 复核和 audit 同步后，持久通道能节省多少 **controller 自身** CPU，目前没有阶段证据。

## 更有潜力的结构方向：复用有限数量的观测 worker

### 已有路径确认每次仍启动进程

R24 `execute_inner` 每次调用 `arguments(..., Slave, ...)`，再经 `captured` → `spawn` 创建新的本地 `/usr/bin/ssh` slave。Python status/read 的远端命令仍是固定 `python3 -c ...`。ControlMaster 复用的是认证连接；command 的 OnceLock 只复用命令文本，都没有让这两个每次调用的进程成为长驻请求处理器。

长驻通道可以把一次 worker 启动成本摊到多条固定只读请求，在对应统计口径下减少进程数量、调度和解释器初始化，机制上比几次字符串分配更有潜力。收益幅度未知；远端 CPU 和端到端 wall 改善不能冒充 controller CPU 改善。一个明确口径下的简单成本模型是：每代固定成本 F、处理 k 个请求、每请求新增 framing 成本 E，则潜在摊销收益为 `F × (1 − 1/k) − E`；当前没有 F、E 的实测值。

### 这不是把当前 child 留着不退出

| 当前契约 / 原代码位置 | 结构改造必须补齐的内容 |
| --- | --- |
| `captured` **987–1028** 同时等待 stdin 完全写入并 shutdown、stdout/stderr EOF、原 Child wait；成功返回以这套闭合为前提。 | 有长度上限的显式请求/响应 framing；不能再把 EOF 当每条响应结束。stderr 和缓冲区也须有独立上限。 |
| `BOUND_OBSERVATION_CODE` **2627–2646** 先 `json.load(sys.stdin)`，status/read **3382 / 3624** 再读取重建的 stdin。 | 当前 JSON 流消费依赖 EOF。必须明确每帧输入、固定 op、请求序号、worker generation，以及错误/迟到帧的归属。直接去掉 stdin shutdown 会使当前协议等不到请求完成。 |
| 每个单次 child 天然只对应一个 Request；reply/output 不会混到另一条调用。 | 一条请求的 timeout/cancel 之后不得把迟到响应交给下一条。原请求不自动重试；帧未知、worker 退出或绑定不符要保留失败，按原 owner 关闭/回收该代。 |
| `OwnedChild._permits` **490–499** 保留预算到真实 wait/reap；`Captured` **93–97** 保留输出预算到调用者消费完。 | 长驻 child 不会按请求 reap。必须分别证明 worker 数量和逻辑请求/输出预算，而不是在 child 仍活着时提前归还原 child lease。需要新一层有界 worker registry / generation 生命周期。 |
| 原 profile、agent、host/master/socket/peer 和 post-response 权限检查均按请求执行。 | 可复用传输进程，不能借此缓存授权、job 内容、FD 或校验结果。每帧仍绑定既有 job_id/job_dir/unit/digest，并重新做原 private-directory/metadata/owner 检查和期限栅栏。 |
| pool shutdown 必须回收原本地 children；当前 helper 是短命、有界工作。 | 长驻远端 helper 需明确 controller 死亡、链路丢失、EOF、idle/总生命周期期限和原进程回收。新 worker 的 ACK 不等于清理已完成，不能默认 SSH 断开就证明远端没有残留。 |

最初范围若继续设计，应限固定只读 Python status/read；不能顺带把 start/cancel、任意 command 或具有 sudo 能力的 jobctl 放入长驻通道。保留两个 host 槽、全局/等待/输出预算需要明确的新证明，不是默认增加 worker 数。以上是当前单次协议不能直接复用的实质约束，并不证明持久化设计在原则上不可行。

### 仓库里有相关先例，但没有现成替换件

此次检查了接受 R24 的以下源码，并结合已保存 R25–35 patch / pool 快照：

- [`stream_broker.py`](sources/src/mcp/runtime/stream_broker.py) **292 起** 有长驻 daemon 和 Unix socket 控制协议，但用途是 **controller-local** 自愿 stdio FD 交接，设计上独立于 MCP 生命周期；它不是跨机 job observation worker。对应 [`stream.rs`](sources/src/mcp/runtime/stream.rs) **97–137** 的每次 `invoke` 仍启动本地 Python helper，不能原样拿来消除每调用进程。
- [`multi_read.rs`](sources/src/mcp/runtime/multi_read.rs) **31–78、91–119** 已有同 host 的 **1–16 文件**批量读取，单次 `run_python_json`，共享响应字节上限和逐文件授权。其 [远端 helper](sources/src/mcp/runtime/multi_read_host.py) 明确不是跨文件原子快照，失败不返回部分文件内容。这是文件能力，不是 durable job status/read 的批量协议。
- 已检索 R25–35 的相关 patch / pool 快照没有实现这个持久 observation 通道。R27 是借用序列化；R30 是 router；R31 是取消等待；R33 是路径处理；R34 是 direct cancellation reserve；R35 是分配/所有权调整。这个结论仅限已检查的公开材料，不扩张到未发布历史。

显式 job batch 也可能摊薄一次 SSH/helper 启动成本，但它是新 API/协议工作：每项保持原 identity、deadline、audit、输出 byte/offset/eof 契约；慢项不能悄悄续期快项，部分失败与整体失败需明确。它不能透明改善未调用 batch 的现有单请求基准。内部自动 microbatch 还需证明公平性、取消、等待窗口和逐请求 admission，不能按“一批算一个请求”放宽预算。

## 下一步判断所需的最小证据

先利用已有原报告区分 controller、ssh descendants、远端口径；100 ms 采样的缺失不能补造。若决定开展一个独立诊断版本，最少需要把一次请求的 profile 验证、agent 交互、主机/预算排队、spawn/post-exec、SSH/helper I/O、post-response 校验、JSON 和 audit 分开记录 wall 与 **controller 自身 CPU**，并保持原期限、权限、停止/清理、零自动重试和原性能门槛。此报告没有实现或运行这些探针。

只有定位到每次进程创建/协议交付是足够大的成本，才值得投资新的 framed worker 或 batch 方案。如果 controller CPU 主要消耗在仍须保留的权限验证/同步路径，长驻远端 helper 可以改善其它资源或延迟，却未必移动当前吞吐平台。现有证据支持收口这些微优化的全套实验投入，同时保留一个明确的结构研究方向；不支持声称已经达到全局最优。
