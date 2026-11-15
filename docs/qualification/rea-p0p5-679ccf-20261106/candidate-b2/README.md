# Candidate B2：固定 6c 组合原始审计归档

**全替代资格：0；生产资格：0；完整端到端成本收益：未建立；总体结论：NO_GO。**

本目录封存 Candidate B2 已结束的有限验证，保留原始成功、拒绝、准备缺陷和失败。归档过程只读取历史证据，不运行候选 Runtime、编译器、引擎或设备任务，也不改变已有报告的判定。后继 C 的源码和结果不计入 B2。

## 固定组合

| 对象 | 实际固定身份 |
| --- | --- |
| Source commit | `6c224e4d913dd596e44fb936e22b447531f8962b` |
| Git tree | `5d75e3bfdcaa20b43b4f170288b4221ceb9040ad` |
| Runtime | 51,493,184 B；SHA256 `170117339fdeeb6632a6df545fbfba4fce8254f41dd763b55df6b38cee57858f` |
| Build binding | 5,046 B；SHA256 `c5e8d129b2acb434a5de3d4e0510635b07c3b7693e241b98d9935bae1fcc58fa` |
| Matrix summary | 55,971 B；SHA256 `568f5d4d156762f667aa340478e8e471be72c3eaee5c3e802e1459c57915ac33` |
| 固定 libtest 副本 | 97,370,984 B；SHA256 `00c21dbb4c7015c73490da3575b73a186429f4c9c33ac2044a7a1790a362f44e`；取自 B2 GNU libtest 证据目录的 frozen 副本，原 mode 0555 |
| 原版 | rea-agents 6.8.0；原安装、tarball、Node、Provider、SDK/JDK 和原版来源清单由各原始资格报告绑定 |

当前工作树和编译 target 已供后继候选使用；本归档从固定 6c Git blob 取得选定源码，实际二进制只取保存于 target 之外的固定副本。旧 A 二进制、binding、matrix 和四门日志只作为升级/回滚的输入，单独放在 reference 前缀，不计作 B2 的运行结果。

## B2 的实际有限结果

| 门 | 已观察结果 | 边界 |
| --- | --- | --- |
| Rust all features | 2,326 passed，40 skipped | 原始 nextest 和全部阶段日志保留，skip 不算通过 |
| Rust no default features | 2,296 passed，28 skipped | 独立特性组合；最终显式 binary build 另有实际记录 |
| 九个 matrix 阶段与四个 ignored 原版门 | 九阶段通过；四门各实际执行 1/1 PASS | 固定四份原版输入及产生它们的 provenance 保留 |
| JSON / Evidence 116 | parsed 116/116；Evidence state 116/116；完整 response objects 116/116 | raw JSON-RPC frames 0/116，未证明完整原始帧相等 |
| Import 118 | 118/118；38 个 JSON 错误的成员序和 UTF-8 text 38/38；4 个 SDK plain error 4/4 | 此有限集合通过，不代表所有错误与协议边界 |
| 加强后的 import 22 | **20/22 FAIL** | `producer/body-overflow` 和 `import/bundle-overflow` 原失败保留；没有沿用 A 的旧 22 通过结论 |
| JS / TS | 7 个 Node + 原版双 oracle；7 个原始 native worker 回放 | 每份请求、实际 worker 双流、原版观察和完整终态分别保存 |
| Python CI 源码回归 | 20 groups，565 tests，0 skip/errors | 固定 B2 源码回归；这些命令没有执行候选 Runtime 或 Cargo |
| 实际 GNU libtest | 2/2 | 单独门，未加入 Rust full matrix 的分母 |
| 持久 GNU MCP profile | 12/12；4 GNU jobs + 1 synthetic cancel；3 controllers | 5 个原始 job 终态、逐页原双流与实际清理；synthetic cancel 不算 GNU 语义 |
| 六个 Provider profile | 6 个有限组已独立组合收口 | Ghidra 11、JADX 8、Chrome 14；APK 三方 19 正例 + 1 伪造输入 + 4 损坏输入；公开 MCP 6；现场 APK 14 commands/checks |
| desktop + x230 恢复 | 新 R2 两台主机 13 phases、2 个实际 owned jobs、3 controllers | 连接重建、私有 controller kill/restart、原 job cancel、cold readback；没有实际网络分区或主机重启 |
| checkpoint 升级/回滚 | c25 → B2 → c25 → B2，4 phases、17 tool calls、4 次实际 server shutdown | 原全目录 A=100 / B=103；1 个 readiness poll 拒绝，0 次工具/phase retry；完整替代、完整升级/回滚资格仍为 false |
| GDB 生成 recorded core | 1 个实际 GDB、1 个自有 C 程序、2 份 core（各 636,664 B）；2 个完整 payload 比较、2 个 whole-helper 边界、5 个 native 边界 | **2 个 whole-helper envelopes 明确不相等**；公开 GDB 动态适配、成本和生产资格仍为 false |

上述计数来自归档中的固定原始报告。原始 116、imports、JS、GNU libtest、provider、recovery、upgrade 和 GDB 组件的外层 job、完整日志和独立消费者结果分别保留，不把进程 exit 0 单独解释为功能资格。

## 必须保留的 RED 与修正来源

Provider 的原 B2 总 driver 确实 failed/exit 1：前五组通过，第六组实际 14 条子命令和检查已经执行，但总 driver 的后置消费者缺少三个准备常量。修订仅从已审核 A driver 的精确 AST literal 引入这三个常量，并只读消费原 B2 14 条命令、完整双流和安装前后身份；未重跑第六组 payload。最终 composed receipt 引用原 RED 与这次只读消费者的实际完整终态。

Chrome 的 instrumented exec 环境观察与未注入 capture/cancel 分开。constructor 收据只证明被注入的那次 exec 边界；8 个真实 Chrome 环境负控制及 executable receipt schema 拒绝门保持，未把空环境映射当作通过。

GNU 原 profile 的 memfd 名称不能当磁盘路径读取，R1 的失败保留。R6 对实际原 pidfd/PID/start/session/group 所绑定的 /proc executable FD 读取精确内容、四 seals 和元数据；独立 R7 消费者准确绑定实际外层 /usr/bin/python3 argv，并明确没有补造解释器二进制证明。原 payload 没有为这次消费者修订重跑。

多主机恢复 R1 的私有 authority 初始化缺失，原 admission unconfirmed、cleanup false 均保留；只读诊断确认没有分配/启动 native worker job，不能把该轮改成通过。R2 在全新私有 roots 中按 B2 required owner-fence 契约 create-only 建立 authority，保留原 13 phases/RPC/预算。原 job 在 cancel 和 cold readback 中身份一致，所有三个私有 controller 实际退出并清理。

升级/回滚原 R1/R3 失败、R3 至 R8 的外部观察/清理/decoder 修正与原 source proof 都在选集。R8 的独立收口明确限定完成的四阶段行为，没有把原版 whole-helper 或 raw wire 不同的部分解释为等价。

GDB R2 实际生成了两份 core 并完成 payload 比较，但 driver 在进程退出后拒绝 systemd 清空 ControlGroup，外层为 RED。R3 仅接受已登记、同 InvocationID/ExecMainPID、原 pidfd 已终止且原 cgroup 路径确为 ENOENT 的终态转换；live 登记门保持。R2 失败和 R3 新实跑分别保留，R3 的独立消费者核对了 156 个原输入前后字节。它没有把两个 whole-helper envelope 差异改为通过。

## 归档和审阅

- [关键原文报告](summaries/) 是逐字节副本；文件名调整只为审阅，原 path / bytes / SHA256 在索引中。
- [逐文件索引](file-index.json) 包含原主机、原路径、归档路径、原始身份、bytes / SHA256、Git blob 与每项明确 omission。
- [分片清单](parts-manifest.json) 给出顺序、各片 bytes / SHA256 与整个压缩流 SHA256。每片不超过 60 MiB，只有一条 gzip 流，不产生未分片的大中间文件。
- [最终发布闭合收据](publication-completion.json) 绑定打包、远端 postflight 和独立消费者各自的实际完整终态。
- [归档最终核验](archive-verification.json) 在原打包 outer 和远端只读 postflight 完整结束后生成：逐成员读取实际 tar bytes/SHA、核完整成员集合、全部 gzip/分片 EOF 和原始来源前后身份。
- [原始打包终态](publication-original-outer.json) 和 [远端 postflight 原始终态](x230-postflight-original-outer.json) 证明归档动作本身的实际结束；它们不是新的 REA 功能测试。
- [归档程序和准备](publication-provenance/) 在 tar 内保存；执行脚本和固定 plan 另保存在任务的 b2-archive-preparation-r2 目录。

可按 parts-manifest.json 的精确顺序拼接分片，得到一份标准 tar.gz。核验工具直接读取分片流而不解压到文件系统。file-index 的 remote_postflight_required 表示打包时独立远端复核尚待收取；最终 archive-verification.json 必须明确证明该后置条件已满足，才能把归档视为完整。

## 发布时的明确排除

原 APK 测试 PKCS12、六个 recovery token 文件、六份包含 fixture signing 密码参数的完整原文件均留在原处，公开归档仅保留其路径、bytes、SHA256 和省略原因，不写入任何秘密字节。没有把脱敏副本冒充原始报告。固定 Git 范围内发现 credential-like literal 的源码也整份省略并保留 Git object 身份。

重复 Runtime/libtest/ELF/Mach-O/PE 对象按 SHA256 至多写入一个实际 payload；全部原路径及所选 canonical archive path 保留。软链只记录 lstat 和 link-target 身份，不跟随；非普通文件、缓存和既定协调 artifacts 按索引省略。编译 target、原版 npm 安装树、引擎、SDK/JDK、工具链和缓存目录没有归档，仅保留原始安装身份清单。

credential 检查包括已知自有 token/signing 字节及编码、结构化 credential 标记，以及有界 gzip/ZIP 展开。损坏输入保持原样并明确记录容器扫描状态；这不构成对任意未知编码的“绝无秘密”保证。当前扫描发现的原六份 signing 参数文件全部省略。

本归档没有新增 IDA/Hopper/JADX/Ghidra 全操作、ADB/Frida/LLDB 或真实设备资格；也没有把六主机路径库存当作动态能力通过。P3 read_function_instructions 等下一候选源更改、C 的回归/矩阵、后续成本准备与运行不混入 B2。完整成本、生产条件和全量替代仍需后续固定组合的适用门。
