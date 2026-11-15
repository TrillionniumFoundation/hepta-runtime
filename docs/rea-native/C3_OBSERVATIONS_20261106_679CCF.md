# C3 固定组合观察报告（Core812、有限成本与证据归档）

**总体结论仍为 HOLD / NO_GO。** 当前登记的 229 个原版操作中，完整资格通过数为 **0**；23 项部分实现、19 项相关实现、187 项缺失，全部 229 项保持 OPEN。下面的测试分母用于说明已经获得的有限证据，不能替代逐操作资格账本。

## 1. 固定候选和原版

| 项目 | 固定身份 |
| --- | --- |
| Rust 候选 commit | `c74737d0e4a36120608a7f89327428e0a666f409` |
| Git tree | `d9841c6f39e5e848d51192ec90223a826b6af355` |
| 集成父提交 | `249639e5ef33de444abb5c506cb089de31e20fce`、`b3bac9e47fd09ee2c6bb0d62802bd55b7662f366` |
| Runtime | 51,620,616 B；SHA-256 `8ae1359ca211afd09c6bdd9e00a9903680867b56b7c19a7986f11796b180e18b` |
| Build binding | 5,047 B；SHA-256 `3fea4fd83dff88d3516c28159dc7bd3d57b509128d336e3c55fa538daec420e2` |
| 原版 npm | REA 6.8.0；包 9,944,902 B；SHA-256 `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb` |
| 原版 Git | `93b8b82db70279e40f484114cff9dc1958dc14ee`；Git 234 个操作，npm 229 个操作 |

Git 与 npm 的行为等价性尚未建立。C2、单独 b3 分支和此前候选的执行结果保留其原身份；本报告只在明确说明的原版参考或方法依赖范围内使用它们。

这次集成包含 24 个变更文件，六个冲突文件经过逐项审查。已执行构建采用 opt-level 1、debug assertions 与 overflow checks，不能作为 release 构建的性能结论。文档发布提交与实际执行的源码提交分别记录。

## 2. 构建与源码回归

九个构建/验证阶段通过，四个补充原始测试各自实际运行并通过。all-features nextest 为 2,361 通过、40 跳过；no-default-features 为 2,331 通过、28 跳过。Python 回归的 20 个分组共 643 项通过。源码选集固定为 1,459 个文件、87,518,811 B，选集摘要 `f70ee5e0abed719cd2a21a5ca320d896103c2dd799830a2e8a2b52950381feb2`。

这些结果支持该固定组合的构建与现有回归；原版操作资格仍按完整契约和真实适用条件逐项判断。

## 3. Rust Core 与 Evidence 的实际对照

| 对照组 | 已观察结果 | 保留的资格边界 |
| --- | --- | --- |
| JSON116 | 116/116 解析值、状态和完整响应对象通过 | 尚无原始传输帧逐字节等价证明 |
| Import118 | 118/118 通过；可比较的 112 个未改动完整 CallToolResult 为 112/112 相等 | 38 个 JSON 错误文本的 UTF-8/成员顺序及 4 个普通 SDK 错误单独计数 |
| Strict22 | 22/22 通过；2 个 JSON 错误文本对照 | 完整 CallToolResult 门为 null，不能转写成 22 个完整响应通过 |
| JavaScript | 7 个双 oracle 一致，7 个 runtime 契约通过，7 个原 worker 对照通过 | 保留各自分母 |
| GNU libtests | 两个固定测试各 1 passed / 0 failed / 0 ignored | 真实外部工具和边界范围按原测试保留 |

升级/回滚试验实际覆盖 old-initial、new-checkpoint、old-rollback、new-explicit-resume 四阶段，共 17 次应用调用、4 个私有服务器、220 个 checkpoint payload 成员和 2 个 metadata 成员，1,715 个输入重新校验。恢复了 3 条原记录、3 个 Unknown 修订以及 5 条混合记录。冷启动为空、显式 resume 后恢复是本次观察到的行为；自动持久化及完整生产升级资格尚未建立。

Core812 已在本次固定 C3 上完成原版执行、原版独立审计、native 执行、native 独立审计和最终产物核算五个阶段。五个原始作业均为 exit 0，stdout/stderr 完整且持久化，原始终态确认完成；没有取消、超时或自动重试。

新的原版 direct API 与 helper 在 812 项中全部一致。独立消费者逐条核对实际原始输入、输出、stderr、exit 和错误结构，确认 **497 个成功、313 个 CoreFailure、2 个原 runtime 包装异常**。native 的 payload／类型化结果 **812/812 一致、零差异**，三类结果分别保留。41 个边界案例包含 19 个输出预算案例；正常完整回复为含换行 1,454 B，最小观察到的完整成功预算为 1,454 B。两个保持 stdin 打开的自有进程均在外部 1 秒 deadline 后被终止并回收，stdout/stderr 均为零。这证明的是外部 harness 的自有进程处理，公共 Provider 的取消契约仍未取得资格。

完整 helper 层报告的资格计数为 **0/812**，不能由 payload 的 812/812 替代，也不能据此推断 812 项都发生了实际 envelope 比较不等。执行前后核对了原版环境的 12,742 个安装文件及固定模块、语料和候选身份；这是端点身份核验，不是连续依赖监控。此前 775 相等／37 admission 差异的历史结果没有作为本次 oracle。

本组保留了两条证据边界。第一次实际 reference 在 driver 启动前，被准备器额外要求安装清单全局排序的条件拒绝；清单本身的固定字节未变。修订仅保留唯一性和完整路径集合核验，原 RED 仍保存。第二次 reference 的最早 start/read/status 原文因尚未落盘而在中断后从本会话的实际工具返回逐字恢复；没有重发 start 或猜补字段，恢复说明随执行树保留。后续终态和完整输出来自原持久作业的实际读取。

最终接受集合为执行根 **29,455,586 B**，加 closure receipt **6,660 B** 和真实第五份 original outer **5,155 B**，合计 **29,467,401 B**，小于 **536,870,912 B**。64 KiB 的预留上限没有当成实际字节计入。独立 handoff 是另外的出版元数据。

证据：`candidate-c-r3/core812-r2-handoff.json`，11,368 B，SHA-256 `46b593bfdf606bf6e64c035e439429cad478d2fbe495755cc2a561dfdda861e9`；其中分别固定了四个阶段的原始 outer、阶段报告、第五份 closure outer、原失败和 start 恢复说明。

## 4. 成熟引擎与主机能力

六个有限 Provider profile 的生产者、独立消费者和最后封存均已闭合：Ghidra 11 项、JADX 8 项、Chrome 14 项；APK 三方对照 19 正例、1 伪造例、4 损坏例；APK MCP 6 项；生成 APK 的 14 条命令中 12 条正常成功、2 条正常拒绝。

Ghidra instructions 使用固定 REA 6.8.0、Ghidra 12.2 和原始 Java 桥接源码。两个函数窗口的地址、文本、符号和函数体分别为 2/2 一致；limitations 为 0/2 一致，两个差异均保留。独立 GNU 对照覆盖 22 条指令、56 B。terminal-call 与 Borland SEH 启发式各在两个窗口中均未触发，不能算作已验证。

该组 R1 在唯一原始 Unix socket 连接时得到 ECONNREFUSED，原版分析已完成但 native 作业尚未启动；自有进程清理已闭合。初始 socket mode 未观察到，其原因仍未被追认。R2 实际观察到了同一 socket inode 的 0700→0600 转换，observer 与原 Java 的 Umask 均为 0077，只有一次 connect，零 retry。首次控制器启动 RPC 缺少返回，状态保留 UNKNOWN；随后相同请求和幂等键的对账返回 reused=true、retried_launch=false。新的只读审计核对了实际持久作业与结果，原来要求首次 fresh-start 响应的门仍为 false。

持久 GNU profile 覆盖 12 项检查、4 个真实 GNU 语义作业和 1 个合成生命周期作业，3 个私有控制器、5 个原始完整终态以及 2 个自有 SIGKILL/restart 场景均有记录。

GDB 使用同一自有 C 程序生成两份各 636,680 B 的 core。两份完整 payload 均一致，whole-helper envelope 均不相等；5 个 native 边界另行验证。这些结果不覆盖公共实时 GDB adapter。

双主机恢复使用 desktop 与 x230，共 13 阶段、45 对 RPC、2 个原 worker 作业和 3 个私有控制器。实际验证的是 TCP 断连和私有控制器重启；主机重启、网络分区、全多主机矩阵及真实设备负载尚未覆盖。

## 5. 生命周期与成本试验

新的 c3-1g-r2 生命周期已经完成 normal、nonzero、dual-control-loss 三案例及独立 witness。原始退出分别为 0、1、-9、0；独立消费者与发布者均成功，active stop 路径实际触发一次。源码矩阵、四个原 gate、留存 libtest 复制来源和当前字节身份在独立消费中重新核对。

固定接收集合为 ROOT 的 280 个文件和 37 个目录，加六个外部原件、consumer receipt/outer、publisher seal 和真实 publisher outer，实际合计 **13,531,307 B**，小于 67,108,864 B。原 libtest 的 98,757,064 B 留存副本是已有输入依赖。此次不复制其内容作为新试验产物。三个 lifecycle 案例的应用、MCP、REA、候选调用与性能样本数全部为 0。

上一轮 c3-1g-r1 的 normal 已成功；nonzero 在 adapter/unit/fixture 准入前因历史 TARGET libtest 缺失而失败，crash 和后续消费者未运行。该 RED 保留原样。新轮采用明确的留存来源证明，历史路径和执行记录均未改写，缺失原因仍为 UNOBSERVED。

普通成本试验已经闭合 **40 次行为预检、240 次实际测量调用**。预检为 4 个行为样本、0 个性能样本；测量为 24 个样本，合计 **28 个私有 unit、280 次调用**，覆盖固定的 20 种请求。独立 F 的实际状态是 **PASS_FINITE_PROFILE**，`finite_profile_qualified=true`；完整成本收益、完整 I/O、release 构建、全目录替代与生产资格仍全部为 false。生产者、两个阶段的独立消费者和两次留存检查均保留各自完整原始终态。280 次调用的值、结构化成员顺序和嵌入文本 UTF-8 均由独立消费者核对；外层 wire 字节等价未由此取得。

每个 profile 使用三个 R–N–N–R 区组（R 为原版、N 为 native），各实现有六个样本。下表为六个实际样本的算术平均；内存列是每个样本 cgroup charged peak 的平均值。

| 固定 profile | 实现 | 样本数 | CPU 均值（秒） | wall 均值（秒） | charged peak 均值（MiB） |
| --- | --- | ---: | ---: | ---: | ---: |
| small5 | REA 6.8.0 | 6 | 7.478 | 8.067 | 291.582 |
| small5 | Rust native | 6 | 0.275 | 0.400 | 31.871 |
| overflow15 | REA 6.8.0 | 6 | 19.026 | 21.516 | 406.417 |
| overflow15 | Rust native | 6 | 3.178 | 3.924 | 132.234 |

三个区组分别计算 native 两样本均值／原版两样本均值，范围如下。这里的最小值和最大值描述这三组实际观察，**不是置信区间**。

| 固定 profile | CPU 比值范围 | wall 比值范围 | charged peak 比值范围 |
| --- | ---: | ---: | ---: |
| small5 | 3.60%–3.78% | 4.65%–5.22% | 10.82%–11.08% |
| overflow15 | 16.57%–16.95% | 17.93%–18.59% | 32.33%–32.76% |

计量包含 measured cgroup 中的 Python client、MCP server 与后代，CPU 取原始 `cpu.stat`，内存取 `memory.peak`，wall 为 clone 开始到组空的单调时钟区间。控制器、输入核验、编译与其他组外准备开销不在这项测量内。每个 slot 前，两方 runtime 与原版完整 npm resolution tree 都在计量外读入并哈希，因此文件系统缓存已被预热；没有清缓存，也没有 cold-start 结论。内存是内核向新 cgroup 归属的 charged bytes，先前已归属别组的共享或文件缓存页仍留在原 charge owner；它不是进程树 RSS，也不是整机增量内存。当前 opt-level 1、debug assertions／overflow checks 配置未作 release 构建。结果仅适用于这台主机、固定 20 请求及上述计量边界，不外推全产品或完整 I/O 成本。

两方使用相同 1 GiB 内存、零 swap、64 tasks、CPU100 和 180s unit 上限。隔离窗口暂停了本任务的其他构建、引擎和取证工作；没有声明共享主机上所有其他服务都停止。

最终测量后的留存核算已经闭合：实际总量 **639,399,395 B**（上限 2,147,483,648 B），其中 common **12,476,611 B**（上限 67,108,864 B）。ROUND 为 **614,109,470 B、3,563 文件、216 目录**；三个固定导出文件共 **25,255,780 B**，完整哈希已核对且未删除。ROUND 在此留存步骤采用文件元数据／库存摘要，没有逐内容重新哈希；F 对其原始输入的内容消费仍是另一条已保存证据。639,399,395 B 是关闭时快照加实际 receipt 与 original outer 的核算，不包括之后 unrelated metadata，不是持续磁盘配额。

预检时的留存快照 116,683,022 B／common 5,490,983 B 作为先前阶段保留，没有用它替代最终测量留存。留存步骤自身新增调用和性能样本均为 0，也没有单独提升行为或成本资格。

证据：`limited-cost-c3-1g-r2/publication/measured-r1/qualification.json`，1,120,741 B／SHA-256 `ada99eaef5476268f8f5e4b205a447c93c0e233eee1c10dec4c99b067ae84fa1`；独立 F 的原 outer 7,045 B／`ae62ad1635a28de0d556a3fe8e9373266f0510b16b0ebde4dac69812a020dfd4`。最终留存 receipt 6,364 B／`566075d4d8236681fb2fb34b43dd17f945731a05da4b54c8ca33d519b770c376`，原 outer 7,190 B／`9c36a25f8470c6e5e67cb38dfc8310550c79c685bd297fd9a2cc6330a3879a98`。闭合 handoff `limited-cost-c3-1g-r2-handoff.json`，28,003 B／`494e301e69780c957aecfe87efa047edbd5ad710a7a9457d0f945d2d1bbfec13`；表中数值来自原 F 及独立逐样本重算的 metrics（2,684 B／`f36b3742d9c342b7109acbe8e9d60a1357dc24aa047cb7007a62f47e536502fc`）。

R3 配置生成曾在应用启动前失败：真实固定 profile 的 expected_export 有 path、bytes、sha256、records、unknown_revisions 五个字段，准备方法误将它与三字段文件身份直接比较。R4 保持完整 profile 和原始请求参数不变，先严格核对五字段及两个非负整数语义计数，再投影 path／bytes／sha256 作身份比较；13 个针对性纯函数控制通过，实际 all-false 配置和生成记录已闭合。旧十个 owner 控制使用三字段合成输入，未覆盖这个真实输入形状，不能追认为覆盖。

原版调用需要的固定导出路径已通过独占创建取得 owner 证明。预检与测量关闭后均重新校验了三个实际导出文件，并分别核算 ROUND、owner metadata、实际 receipt 和原始 outer。两阶段原件独立保留。本组 17 项真实主机计数事实与 35 项合成 consumer 控制分开保留；计数校准只支持 CPU、内存和 wall 方法，应用比较由本次实际 40＋240 次调用支持。完整 I/O 成本资格仍未取得。

旧 C2 的 512 MiB 预检只实际发出 11 次调用，其中 10 成功、1 次原版资源拒绝，240 次测量没有启动；该结果不转化为新轮成功或性能收益。

## 6. 归档方法及交付状态

新的归档方法使用受保护路径的名字级排除，在任何文件元数据或内容操作之前完成准入判断。原受保护对象不产生大小、哈希或存在性证明。选集中被省略的普通原件仍参与集合和不变性核对。

独立复核发现原 C3 R3 的流式 tar 校验可能接受合法 tar 后 24 B 非零尾部；该实际 RED、输入、分片和旧接受结果均已保留。R4 在全部解压读取上统一记录最后非零字节位置，验证最后成员边界、两个零结束块和块对齐。17 组有限控制通过，包括同一原反例、块对齐非零尾部、缺失结束块、结束后第二份 tar、空文件、含零数据及 PAX 长 Unicode 路径。此检查没有追认旧 C2/R3 归档。

R5 的新增复核还发现一个独立问题：gzip 后段 CRC 错误会丢掉先前已经观察到的 hard credential marker。这个合成输入上的原 RED 保留；最窄修订改为调用方持有命中集合，gzip 和 ZIP 当前 entry 在异常前观察到的标记都不会丢失。新增 25 项针对性纯函数／小文件控制通过，包含同一 gzip 原反例和 ZIP 后段 CRC 反例，且硬标记不能通过 fixture 审阅重新准入。旧 tar 17 组没有重跑，也没有与新增 25 项合并。

x230 的固定自有根已完成实际 inventory、两次原始 UTF-8 运输以及修正后的独立只读消费（实际 inventory rows 的 revision 为 `r1`，旧草稿 `c3-r1` 仅是历史标签）：31 个文件、272 个目录中，29 个 UTF-8 文件共 115,424 B 进入运输，runtime 和 token 两个对象保持整件省略。第一轮 64 目录上限的失败，以及后来 sealer 产生的无效 JSON／换行哈希错误原件均未改写；修正消费者重新消费原运输记录，没有重做 inventory 或运输。打包后的实际 postflight 已重新核对同一固定文件集合；其原始终态与独立归档消费分别保存。

源代码来历已另行闭合：保留 commit/root-tree 原对象、两个父提交完整的 raw delta／名称／状态，以及选中源码的完整 patch。相对第一个父提交 24 个变更路径均在源码选集中；相对第二个父提交 183 个变更路径中，87 个在选集中、96 个在外。原始大 diff 超过 8 MiB 的失败也保留。没有声称对历史整个 Git 树递归重算全部对象 SHA-1，Git 配置与 attributes 也没有独立冻结。

固定选集已完成名字准入、逐文件内容判定、归档生产、x230 postflight、独立归档消费及准入交付文件清单闭合。六份 Provider 大元数据仍仅按固定字节和九项文件身份提取依赖，共读取 32,490,306 B 的已有元数据；没有遍历或复制工具安装目录。安装环境自足性和完整传递依赖闭包均未建立。归档完整性通过不提升原功能、全量替代或生产资格。

准备与失败历史单独保留：resolver R1 因 scope 将 preparation receipt 的 pin 误绑到 prepared-inputs 路径而实际 failed1；R2 只纠正 anchor301，随后实际成功。另一次 metadata 读取上限修订发生在成功 scanner 产出 35,978,020 B inventory 之后，在实际 projection／pack／consumer 运行之前将相应专用上限改为 40 MiB／64 MiB；这不是这些后续阶段因 32 MiB 上限而实际失败。最终 file-index 为 46,575,046 B，小于 64 MiB；扫描算法与资格门未改。

| 实际归档或交付量 | 原记录 |
| --- | ---: |
| 压缩分片 | 4 份，共 201,397,624 B |
| 归档成员 | 28,980 个，共 1,678,657,092 B |
| 准入交付文件（不含三项仅名称排除的运行时条目） | 23 个文件，共 249,842,525 B |

completion 与 flat 原件仍保留 `LOCAL_DELIVERY_INDEXED_PENDING_FINALIZER_OUTER` 及 `actual_whole_delivery_closed:false`，因为两者发布时自身 outer 尚未形成；本报告的交付闭合依据还包括随后成功、完整且耐久的实际 finalizer 原始 outer，未改写这些原件。准入交付文件总量不包含目录外的 flat 和 finalizer outer；它们作为两份外部 custody 记录分别复制。物理目录另有三项受保护运行时名称，文件类型、元数据、大小和 SHA 均未知；此总量不代表整个物理目录。

交付 finalizer R1 真实 failed1：预定 22 个文件均在，但目录根另有三项受保护运行时名称，因此原完整名字门拒绝。三次精确 file_info 均被能力边界拒绝；未绕过该边界读取、stat、hash 或删除它们。R2 仅在固定 D 根、对子项元数据访问之前排除这三个精确名称；其他额外名、缺失项、错误目录下同名以及 PUB3 目的目录均维持严格拒绝。成功 R2 仍只登记 22 个原准入文件加 completion，不是对三项运行时条目内容的确认，也没有重打归档。原 R1 失败、名称诊断、拒绝原文、新方法／差分／控制／实际发布与原始终态在机器事实 `archive.postpack_delivery_revision_provenance` 中逐件保留原 bytes 的 base64、长度、SHA、角色与来源路径；本地 renderer 只核这些封存 bytes，不重跑交付方法。

实际选集为 **661 个声明根、894 个 anchor、535 个归并 scope**；scanner 元数据记录 **27,865 个 desktop 条目、10,835 个 Git 条目**。16 项严格内容 hold 各有明确决定：**8 件原件整体省略、8 件精确审阅 fixture 纳入**，没有硬标记覆盖放行。52 个 required Git pin 身份均匹配，但仅 51 件 payload 纳入、1 件因硬标记整体省略；APK 子树 25 个成员身份匹配，先前只给 hash 的 8 个 Git 与 9 个 owned 条目均匹配原 SHA，实际尺寸由原 scanner 元数据取得。这些分母描述选集或内容身份，不等同于归档成员数或操作资格。

历史 28 个 mismatch 与 415 个 skip 均已逐项审阅，但**没有全部解决**：仍保留 5 个 mismatch、3 个 sealer 引用及 2 个本地缺失源码引用；86 个相对 Git 引用仍待上下文，109 个环境引用只保身份，旧 Chrome receipt 仍是 `UNSELECTED_GAP`。这些类别可能交叠，不相加成新的缺失总数；完整原数组、原 bytes 与处理理由继续留存。实际 corrected scope、base/addendum、resolution、inventory、projection、content-review 的完整远端 pin 直接列于机器事实 `archive.actual_selection`；旧草稿的 655／868／17 仅保留为历史。

## 7. 资格和后续完成依据

本报告保持逐项区分：构建回归、原版结果、typed failure、完整 CallToolResult、helper envelope、嵌入错误文本与原始传输帧。有限引擎检查、私有控制器恢复、通用生命周期和本地方法负控制分别保留各自适用范围。

只有固定组合上的实际执行、原始输出与终态、独立消费、输入不变性和所要求的完整预算均闭合，才会提升对应有限观察状态。229 操作全量替换、完整成本收益、release 构建和生产资格目前均未通过。PR 保持未合并，未部署。

## 原始证据定位

最终机器可读事实的相对路径：[C3_OBSERVATIONS_20261106_679CCF.json](C3_OBSERVATIONS_20261106_679CCF.json)。归档须以 file-index 将每个原始绝对路径映射到实际归档成员及分片，并明确省略的安装环境、凭据和历史归档依赖；外部依赖不计作包内自足证据。

以下归档身份在原结果与实际终态闭合后绑定；文档提交和远端更新由后续外部发布回执记录。

| 收口项 | 已绑定内容 |
| --- | --- |
| 最终成本阶段处置 | PASS_FINITE_PROFILE；40 次预检＋240 次测量，24 个性能样本；全量成本与生产资格 false |
| 最终成本原始结果与独立消费 | `limited-cost-c3-1g-r2-handoff.json`，28,003 B／SHA-256 `494e301e69780c957aecfe87efa047edbd5ad710a7a9457d0f945d2d1bbfec13`；F、原始 outer、最终留存 pins 见第 5 节及机器事实 |
| 已验证归档 README | [README.md](../qualification/rea-p0p5-679ccf-20261106/candidate-c3/README.md) |
| 归档 manifest 原件 | [parts-manifest.json](../qualification/rea-p0p5-679ccf-20261106/candidate-c3/parts-manifest.json)，1,059 B／SHA-256 `77e97d3407d61d9c6d5ce9ba2184d5787b0e5566f8f0d63b0a0ef1696fba5455`；固定 archive-plan 的原路径与 pin 见机器事实 |
| 完整 delivery inventory | [delivery-file-list.json](../qualification/rea-p0p5-679ccf-20261106/candidate-c3/publication-custody/delivery-file-list.json)，6,752 B／SHA-256 `ae233f60c7911b51a8c20d3f03945812cd02f16c4037526814e6ca53b654b050` |
| producer／postflight／consumer completion | [completion.json](../qualification/rea-p0p5-679ccf-20261106/candidate-c3/completion.json)，26,278 B／SHA-256 `939651b793bae5ebe213564e765f98f54216b6e3f998403fc061cff853f977c1`；原 pending 字段保持不变 |
| 交付目录的外部来源保管证明 | [delivery-finalization-original-outer.json](../qualification/rea-p0p5-679ccf-20261106/candidate-c3/publication-custody/delivery-finalization-original-outer.json)，5,332 B／SHA-256 `ade2097906bef3068f84aaaab67cb41aa69f27149ea37191050c9c61c7dab08d`；与上述 flat 共同保管来源 |

执行源码固定为 `c74737d0e4a36120608a7f89327428e0a666f409`。本次文档更新的已观察父提交为 `1c8562754ed1c38358be7aad0fdc24c3c940b47a`；实际新文档 commit/tree 由提交后的外部回执记录并写入 PR 追加块，不在提交内容中嵌入自身提交摘要。
