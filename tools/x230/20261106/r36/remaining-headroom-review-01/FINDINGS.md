# R36 validation-scratch 之后：剩余成本与停止边界

## 决策

**当前没有证据支持立即再开一个新的低风险源码候选。先完成当前 scratch 的原 normal lifecycle 验收，再按既定门槛处置；不要把 OBS 单次约 2% 的 C8 差异写成已经证明的因果收益。**

这个结论限定于当前完整验证、取消、权限、owner/worker 与生命周期契约，以及已经取得的源码和 D2 成本证据。它不是“全局再也不能优化”的证明，也不把尚未独立测量的 R32 单独版本声称为全运行时失败。本次没有修改源码、编译、运行测试/解析器/审计器/工作负载或调用 host；只读取 Git/本地原件和做小量整数算术。

## 精确当前源码

两份文件都逐原 byte 重算 SHA256/Git，并命中实际 cold02 Q 的完整 220 输入图（24,156 B / SHA256 `b9eff66ea8b14eca80d16069a59588a551fcf6feff0ac4c991690425df65462a`，Git `6ad5e7759d865ea0f51c67fbcbe53dcb22b6a558`）。

| 文件 | Git blob | 字节 | SHA256 |
|---|---|---:|---|
| src/mcp/runtime/ssh_observation_profile.rs | a68cdc86cd3eed479d21028cdb4a13157376b4f7 | 25,779 | eb7d677f2ca713d4719668202d7808925785f259aa15d6494ae8ec30fed17a3a |
| src/mcp/runtime/ssh_observation_reference_tests.rs | f94301550095e5b99a8adfdfdbbf60dd4016efc4 | 17,240 | 0895a19b655fcb9abbd5fbbc479b8e1c719eadc0185a06e97add539a402d5dce |

生产改动只在第一份：`verify_files_checked` (825–845) 为一次同步 sweep 持有局部 lazy buffer；`verify_checked_with_buffer` (290–349) 仅 SHA 分支创建 Context。测试文件是差分/边界证据，不是生产热路径，也不存在从中删测试以换性能的合理方案。

## 已观察到的成本，不是当前 scratch 的剩余性能测量

数据直接复用已封 D2 recovery02 measured-only 计算：Git `5a256efe675ed3fea408b18712043b1965fb36ab`，23,508 B / SHA256 `b8b6d6257e8347544fb46581908072a90608ece2543b9947a07f60eaf62b95e7`。其原投影 Git `e633612cc65afcd24907382676776938dc10a985` 绑定原 adapter 8,827,749 B / SHA256 `d882031e45096ddddee57dd83b580b5dc3ff15ebe2481b9c9a1dd2d109d44807`。本次重哈希计算文件，没有重新运行其脚本或原 parser。

分母是两轮 ON 各 192 个 measured 请求，合计 384；controller CPU 总计 12,850,000,000 ns，33.463542 ms/请求。D2 带细分诊断且早于当前 scratch，不能把下表当作 scratch 后的实测成本、生产无探针成本或可回收上限。

| 保留阶段 | D2 ms/请求 | controller CPU 占比 | 具体含义 |
|---|---:|---:|---|
| 初次 checked_file | 3.982885 | 11.902161% | fresh 逐级打开、metadata、权限/类型/大小/能力检查 |
| 完整 read + reference 比较 | 6.416265 | 19.173898% | 所有块的 read/比较/原取消与期限检查；不是纯 memcmp |
| 完整 read + SHA | 0.674518 | 2.015681% | private 文件等 SHA fallback 的完整循环；不是 Context 初始化 |
| 最终 verify_read | 3.949858 | 11.803467% | 完整长度、原 descriptor stamp、再次 fresh 路径打开/metadata |
| 额外 verify_identity | 1.743549 | 5.210295% | 边界的完整身份复核；不是可缓存的已验证标志 |
| shell resolution | 2.228946 | 6.660820% | 当前 /bin/sh 链、别名及目录身份验证 |
| profile policy | 0.737173 | 2.202914% | 当前私有目录、已缓存 policy digest、当前 agent 环境比较 |
| worker + owner 父 exclusive | 1.235220 | 3.691242% | 包括本次 scratch/Context 目标，也包括其它原工作与诊断记账 |
| whole validation（父 inclusive） | 20.968415 | 62.660478% | 以上七 child exclusive 加两父 exclusive，不能重复相加 |

初始检查、最终检查、额外身份三段合计 **9.676292 ms/请求、28.915923% controller CPU**。这证明完整文件验证值得关注，却没有分离路径词法/分配、openat、fstat、fgetxattr 等各自 CPU。

七 child 为 19.733195 ms；父 exclusive 1.235220 ms。原整数恒等式是 8,051,871,370 = 7,577,546,820 + 474,324,550 ns。即使假设整个父 exclusive 全消失，其直接 CPU 预算才是 3.691242%；当前改动只涉及其中一部分，不能据此承诺同幅度吞吐收益。

记录到的同步 exclusive 总量是 24.282254 ms/请求；controller 减该值的 signed residual 为 +9.181288 ms/请求（27.436689%）。它混有未记录工作、后台/诊断工作及计数窗口差异，不能归给 SSH、网络或锁。原 controller 计数器 100 Hz，每 tick 10 ms；表的小数只是算术展示精度。

## 为什么没有新的小补丁达到“值得再跑完整流程”的证据要求

### 1. 两个已确认的重复初始化已由当前候选处理

原设计储备 Git `ff2b6e0ea76447d2b93ec5e5449f26c51379679f` 只提出 reference 路径未使用的 SHA Context 和一次六文件 sweep 的重复 16 KiB 初始化。当前代码都已处理。

buffer 直到原 checked_file 与首次检查之后才创建，所有使用严格限于 `buffer[..count]`；两新增测试覆盖长→短→空、reference/SHA 交替和污染 tail 下取消优先级。再改 Option/enum 布局、拆两份读取循环或改栈布局，没有当前机器码/周期证据；编译器可能已消除部分开销，也可能因改动增加代码尺寸或栈成本。不提出这样的新补丁。

### 2. 路径分配还有源层工作，但已是 R32/R33 方向

当前 `open_absolute` (115–143) 仍做 absolute 检查、收集 Vec，再逐组件构造 CString 与 fresh openat。最窄的想法“只用 peekable 迭代器去掉 Vec”在本次查询中被确认 **已经是 R32 原实现**。R33 又在其上为固定 PinnedFile 保存 Arc/CString 组件。

原 R32/R33 每个组件 run 都有 16,384 completed opens。原 allocation report 明确：只统计 allocation 请求，**没有测 CPU、latency、吞吐或 RSS**。浅/深/目录形状 R32 每次从 4/12/10 个 allocation 请求降到 3/9/8；R33 hot 都为零。不能将这些 allocation 数换算成上面 9.676 ms 的可省时间。R33 的正式 C8 拒绝也不能被组件计数覆盖。

因此，单独 R32 仍是已有、尚无绝对 CPU 量级与独立全运行时结果的储备，不是本次新发现。它也没有被此次分析证明“绝不可能有效”；当前不足以因改名或缩小旧补丁就重开全套资格。把 CString 改成额外大栈缓冲同样缺少 CPU 归因，还会重新引入初始化、布局和边界复杂度。

### 3. 大块成本不能靠少做验证合法消除

- `verify_checked_with_buffer` 保留每块前后 check_current、Interrupted 重试分支、maximum+1 限制、完整 EOF 和最终 fence。reference 首块已不匹配也仍比较后块。增大 read 块、稀疏化取消检查、首次 mismatch 早退或以 worker 结果替代 owner 重读，改变现有取消/期限/错误优先级，不能作为同契约小优化。
- `verify_read` (186–202) 的长度→descriptor→fresh path 短路次序，以及 `verify_identity` / `verify_boundaries` (276–282、846–859) 的新鲜校验都仍有用途。缓存 FD、inode/mtime 成功或已解析路径结果会削弱当前接受条件。openat2 直接替换没有保留每级 O_RDONLY/O_DIRECTORY 语义的等价证明，本次不提出。
- `fixed_shell_resolution` (361–466) 与 `verify_resolution` (482–503) 每次读取当前目录/符号链接链并比较原身份；把上次结果缓存为可用，不是纯重复计算消除。
- `verify_policy` (860–867) 不是每次 JSON+SHA。已直接核 accepted config.rs `InstalledRuntimeConfig::policy_digest` (119–147)：OnceLock 缓存成功或序列化失败，读取入口 (398–404) 返回该值。再缓存一次没有目标；私有目录与当前 SSH_AUTH_SOCK 比较仍须保留。
- `OwnerTicket::check_current` 保留当前 cancellation token 和同一原 deadline（Git `ba7448234be22b7736e098c22e874e164fbe9a8d`）。D2 没给出其中 token/clock/同步原语的独立成本；不能把 read-loop 整段成本当成可删的锁等待。

## 既往结果约束

以下是读取既有正式报告/原 gate 的历史事实，不是这次重跑，也不证明各源码改动因果导致差异。

| 方向 | 原结果 | 本轮含义 |
|---|---|---|
| R30 router OnceLock | 2303/2304 measured 成功；一次 10 s transport deadline；拒绝，内部阶段原因未定位 | 不重新包装 router 缓存，更不能将该失败归因网络或源码 |
| R31 pidfd readiness | 组件 helper 变快，但正式 C1 B/A 0.949837922 < 0.95 | 有组件收益也不能覆盖整体必过门槛；不更改取消等待 |
| R32 iterator / R33 CString components | R32 只有 allocation 组件；R33 C8 B/A 0.9484071054 < 0.95 | 当前最明显的路径分配方向已覆盖；单独 R32 没有全运行时拒绝结论 |
| R34 cancel reserve | C8 B/A 0.9306283429 < 0.95 | 不增加容量、保留原 admission/owner/cleanup |
| R35 JSON deferral + command ownership | normal LC concurrent_cancel B/A 0.9293926468 < 0.95 | 不能以其它指标变好覆盖取消吞吐 |
| 旧 R36 audit-cache / PR106 | LC all_operations 0.9461164389、launch 0.8876144915，均拒绝 | 与当前 validation-scratch / PR108 不同；不得混用结果或复用为新优化 |

当前 scratch 的 corrected OBS gate passed 是 root 的实际回报；本报告未重新读取或重算该 OBS。normal LC 仍由原流程完成。本报告不预填其结果，不改变任何门槛、fixture、既有失败或采纳状态。

## 明确停止边界

停止继续编造小 allocation/clone/cache 候选，完成当前原 LC 和证据收口。在当前证据下，**有显著成本的部分必须保留；可保持契约的小计算变化已实施或进入既有 R32/R33 历史，但缺少足以再跑完整流程的绝对 CPU 证据**。

只有以后取得一个确切、尚未覆盖且有绝对成本的机制，才有理由重开源码候选。例如真正量出同契约 fresh path 内纯分配的 CPU，而不是将整个 open/fence 段划给它。这个条件是研发优先级解释，不是新增接受 gate，不要求为本报告另跑诊断。

更大变化如持久 observation worker/batch 是单独的传输协议与 owner 生命周期设计；原先已经记录 framing、EOF、迟到响应、每请求 authority、预算及远端残留的边界。D2 的 residual 不是它的收益证据，当前不会把它伪装成低风险补丁或声称已达到系统全局最优。

## 关键已读原件

- R24/D2 设计储备：`ff2b6e0ea76447d2b93ec5e5449f26c51379679f`。
- R24 config.rs：`4dcf26d2f8d4475abbd0710410463b71e5b198a8`；23,682 B / `961c275dbe205180303ae9affa562af61aa4b0cc29eebbf5f8686c711d9d67d3`。
- D2 已封成本计算：`5a256efe675ed3fea408b18712043b1965fb36ab`；本次只复用，不重跑。
- R30 原说明：`fa98df110754ecb3d2fce6d5f2058a4c7ffd62a8`；deadline 边界：`1358c98042a2a4999ebb20bd5dd612ba3db7db02`。
- R31 原说明：`1f5bf7633c51d858f44a6a89be7629e11b45002e`。
- R33 原说明：`2d27b589ed7f9fe28113b4c6f5204c5eda30a2b4`；原 R32/R33 allocation report：`8ae6b8517305da775f7bbbb2170f20ae410ca0cf`。
- R34 原说明：`20e84e7037cc81d53ffdfdc56b18307209b291e8`。
- R35 原 normal LC gates：`717378626467c399e294bf87e574e27c854eae1c`。
- 旧 R36 audit-cache 原 normal LC gates：`2d699ac8f68069bbb525454e822a797f2ab7cb00`。
- 既有微分配/持久协议边界报告：`dbf3a87b2abf7d259d39eb6aae553672b6c40398`。
