# Candidate C2 — 原始观察与有限资格档案

本目录保存 2026-11-06 固定 Candidate C2 的原始结果、实际失败、来源和逐文件索引。**完整替代与生产资格仍为 NO_GO；完整成本收益没有成立。** 归档完整性通过只表示所列原件、成员和分片相符，不会提升任何功能、性能或产品资格。

## 固定组合

| 项目 | 固定值 |
| --- | --- |
| 源提交 | `249639e5ef33de444abb5c506cb089de31e20fce` |
| Git tree | `51bac4e4095f35bae0149523f773a081f184bda4` |
| Native runtime | 51,604,432 B；SHA256 `c02d4b9ede2206cf8abb6603ca59fab05acb13e54a2d2be339a52140e9126ec4` |
| Build binding | 5,047 B；SHA256 `00a28a67d0cb3bb12acd3ebc1200f67f149159c37ffd8a0cefb48d3be3b196c7` |
| 实际 libtest | 98,541,896 B；SHA256 `a3769d9ca9453fc03a70f7d026ae4c5e559c3c47afeb122621ca6f04d8856191` |
| 原版 | REA 6.8.0；各原始 producer/安装树身份以原回执为准 |
| 主要宿主 | desktop；有限恢复另使用自有 x230 root |

libtest 已独立复制为 regular file、nlink=1、0555，复制和目录均 fsync，完整源前后 SHA 一致。当前工作树和共享 TARGET 不进归档；源码取固定 Git 对象。旧 A/B2 二进制只作为所选升级、对照或来源输入保存，各自 SHA 不变，绝不供应 C2 通过数。

## C2 实际结果与边界

| 组 | 实际观察 | 仍保留的限制 |
| --- | --- | --- |
| Rust 全矩阵 | all-features 2350 PASS / 40 skipped；no-default 2320 PASS / 28 skipped；9 stages 完整结束 | skipped 不是通过 |
| 原版输入 ignored 门 | 4 个门各实际 1/1 PASS | 只覆盖这四份固定输入 |
| Python CI 源回归 | 20 groups、621 tests、完整 OK | 源回归，不声称运行 native runtime |
| JSON116 | parsed、Evidence state、完整 response object 各 116/116 | raw JSON-RPC frame 相等为 0/116 |
| Import118 | 118/118；JSON 错误 exact text/member order 38/38；SDK plain 4/4 单列 | 不扩成所有原版拒绝路径 |
| Strengthened22 | 22/22；新增两个 JSON 错误 exact text/order 均通过 | C2 修复前 B2 20/22 RED 不被改写 |
| JavaScript | 7 个 Node/原版双 oracle 对照及 7 个原始 worker 回放通过 | 固定语料有限门 |
| 额外真实 GNU libtests | 2 个真实门各 1/1 | 单列，不加进 full-matrix 分母 |
| 六 Provider | Ghidra 11/11、JADX 8/8、Chrome 14/14；APK 三方 19 正例+1 forged+4 malformed；APK MCP 6/6；现场 AAPT2 14 命令 | 六组有限 profile；Chrome instrumented exec 边界与未注入 capture/cancel 分开；14 命令为 12 zero + 2 ordinary reject |
| 私有恢复 | desktop+x230 13 phases、45 RPC、2 owned jobs、3 private controllers | 不是实际网络分区、宿主重启、生产服务或引擎负载恢复 |
| Persistent GNU MCP | 12/12 checks、4 real GNU + 1 synthetic lifecycle job、3 controllers、5 原始终态 | synthetic cancel 不代表 GNU 语义 |
| 新 Ghidra instructions | address/text/symbol/body 各 2/2；2 GNU 窗口共 22 行/56 B；native 3 jobs、2 controllers、5 denials、2 restarts | limitations 两项不同；实际 launch cwd 偏离预定，R2 consumer 原 RED 保留；R3 显式 launch_contract=false，不声称全等价 |
| GDB core 组件 | 1 own C、2 own core 各 636,680 B；2 完整 payload 对照、5 native boundaries | 两个 whole-helper envelope 仍不合格；不是 public live GDB adapter |
| 检查点升级/回滚 | 4 phases、17 tools/call；220 indexed files、1712 最终复核文件；0 readiness failure | 只覆盖固定私有 profile，完整升级/回滚与生产资格仍 false |

原始总结的未改字节副本在 `summaries/`。完整 wires、分页日志、原始 owner/pidfd/unit/cleanup 回执、工具配置/安装身份及对应 source/fixture 都由 `file-index.json` 映射到 gzip 成员。不能只凭本表计资格；原始 denominator、原 outer、独立 consumer 和明确 scope 一起解释结果。

## 成本阶段：CLOSED / FAILED_INCOMPLETE

原 512 MiB whole client/server 预检实际启动 3/4 units。small-R 和 small-N 各 5 个调用本地完成；原版 overflow 的第一个 import 已真实写入 stdin 并收到 `resource_constraint`：authentication_bytes=50,437,404，available_heap_bytes=40,351,424。因此是 **11 个实际 tools/call = 10 成功 + 1 资源拒绝**。失败 worker 的 `calls:[]` 是失败发生在成功行追加之前，不能解释为未发送请求。

第四 unit、F5 独立 consumer、240-call measured 均未启动。所有已启动原 owner 和 unit 的终态/清理记录保留。没有 OOM 已发生或 cgroup 预算是唯一成因的推断。原预算不改、没有自动重试、性能样本为 **0**；不提供运行时间收益、CPU/RSS 收益或完整 I/O 成本结论。未来资源配置或 C3 是独立组合。

计量方法历史另存：首次 cgroup 回收/counter 丢失 RED；第二设计 24 MiB fixture 只验证 CPU+memory+wall 方法。Generic lifecycle R1 因 literal 交接超时失败，R2 因 driver 先清理导致独立 active stop 未覆盖失败；两轮均保留。R3 使用明确双 control 故障，2 cases 完整结束并独立证明原 InvocationID 的 active stop 恰好一次；original crash -9 不改。R3 整体实际 8,049,925 B 小于 64 MiB，仍为 **0 application calls / 0 cost samples**，不能替代行为预检或 measured 结果。

## 来源、失败与发布历史

C1 原始取消和日志、P2 source-map 原始 producer/23 focused controls、overflow 两家族原始错误见证、新 P3 schema/原版实际观察，以及所有选入的 preparation RED 都保留。它们各有 source 和 scope，不相互替代通过数。

两份短 host metadata 快照仅表示当时当前 UID 的观测：可见 48 logical CPUs，有背景 Chrome/Python 活动，短样本中没有可识别的 Cargo/rustc 活动。它们没有证明宿主 idle 或未来整个测量窗口 quiet。没有后续探查既有 Python job、Android 服务或个人设备。

共享 PR84 另一路从 42949877 推进至 b3bac9…；两份实际历史快照独立保存。C2 own publication lineage 仍保留 8c2f48d…；旧 expected429 快进方案不再有效。C3 整合与资格不继承 C2。本档案不修改或合并共享 PR。

23 条历史 pin 引用差异对应六个路径：五份 calibration 审阅前版本与一个故意变更的 negative fixture。它们的 declared/observed 身份、来源和可取得旧版本位置逐项记录在 preparation 的 source-release-and-reference-audit.json；所有 declared 版本内容都已选入。原 pin 和原结果没有按现值覆盖。旧草稿的 controller-receipts.json 未生成；实际 matrix-controller-r1.json 已作为原 outer 保存。

## 公开省略与二进制去重

生成 credential、token、PKCS12/private key 及包含其实际值的整个源文件/argv 回执保持在原私有路径，公开索引仅保存原 path、bytes、SHA 和省略原因，不公开值。现场 APK 的两个签名命令回执及含密码的 qualification 原文因此省略；最终有限组总结和非秘密回执仍保留。任何额外 redacted review copy 都必须标为副本，不能冒充原件。

原件中的 symlink 只记身份而不跟随；安装树、node_modules、SDK/JDK/Ghidra、Cargo target、Git 元数据库、缓存、个人浏览器/设备/既有进程内存均不选入。两个 core 来自本轮自有 C fixture。magic 检测的 binary identity 计数包括 ELF object/core，并不是执行次数。

同 SHA 的二进制 payload 最多保存一份，所有原路径与 canonical member 映射仍在索引中。C2 libtest 优先使用已独立固定的副本。归档生成不执行任何候选或 engine。

## 复核方式

1. `parts-manifest.json` 固定顺序、每片 bytes/SHA 和拼接 compressed-stream SHA。每片不超过 60 MiB；原 2 GiB 写前 cap、1 GiB reserve 保留。
2. `file-index.json` 给出原 host/path、archive member、精确 bytes/SHA、类型、重复映射和完整省略理由。
3. 独立 consumer 流式读取全部 tar members，不提取执行；核精确成员集、逐成员原 bytes/SHA、所有 part 和完整 gzip EOF。
4. 原 desktop 文件在实际流写后和独立消费时重核；x230 对本轮私有 root 的 31 个原对象做精确 postflight，不扫描其他位置。
5. producer、x230 postflight、independent consumer 的原始 request/start/read/status 与完整双流终态各自封存；最终 completion/flattened delivery inventory 固定实际发布文件数、总字节和 SHA。

资格结论始终区分归档完整、有限功能 profile、方法 fixture 和完整产品/成本。**Full replacement=false；production_qualified=false；full_cost_benefit=false。**
