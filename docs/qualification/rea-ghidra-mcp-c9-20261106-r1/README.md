# C9 Ghidra：真实 MCP、完整 Evidence 与逐字段差分

这是候选 `c9c79e27a2bf56bd204df6591ca2311dc872e317` 的历史基线，完整上游资格仍为 **未通过**。原始执行、完整结果、失败、导出及关闭证据按原字节保留；后续修复没有反写这些结果。

## 固定身份

| 项目 | 实际身份 |
| --- | --- |
| C9 source tree | `e24bfd8dddb62f58b0bcfd6362c17b7ee7677605551f29a65fc98e44b847764f` |
| Native binary | 51,113,816 B；SHA `56ae3b2313122ae7baae46df5536ee41f898aa09cbea10478a72de7cfe74e7cd` |
| Build summary | SHA `caca443885057c9d7d71251228dd380d22bb7e47d3cdd6706a2eea38b525d6b7`；完整九阶段矩阵通过 |
| 输入 ELF | 15,680 B；SHA `ec301f409d22314b43b4392fa80ada28213cd75ca77c6cbbbbfe1454555dd64a` |
| 原版 npm | `rea-agents@6.8.0`；tarball SHA `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`；验证 2,398 个包内文件 |
| Ghidra | 12.1.4；release ZIP SHA `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` |
| Java | 25.0.5+8；java SHA `1bf1aaef01e4f8d7c85d913c60fb2ee4624cbe54d4053254c59657b7ea913b25` |
| Node | v22.23.4；SHA `94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90` |
| Native profile | `hepta.ghidra.12.1.4.elf-x86_64-default-functions.v1`，ELF loader，`x86:LE:64:default/gcc` |
| Options | 146 个默认选项，26 个启用／4 个禁用；canonical SHA `a5531d741cf6e4e42215ea1f4268049600b80c3a03ab7d3586bd3a7bbb7acd75` |

安装校验覆盖 3,139 个 Ghidra/GPL 文件和选定 JDK 文件。原版完整 146 项快照未在其会话直接采样：默认配置一致性还有固定 npm 源码及实际日志支持，不能把推断写成原版直接快照。原版本次真实诊断显示 NoReturnFix `cleared=0 sites=0 refit=0`；native 不运行该脚本，其他输入仍有差异边界。这里仅覆盖实际 Linux controller 与 Linux x86_64 host。

## 三次真实执行

| 阶段 | 原 durable job | 结果与范围 |
| --- | --- | --- |
| Native full provider harness | `1a1b22234bb-fc05-7c87` | exit 0；13 项有限操作／取消／重启／worker 故障／timeout 检查通过；不是完整 REA 等价 |
| Native 原 job 补读及负例重发 | `1a1b2298c0b-fc05-7cba` | exit 0；producer 23/23；独立复算仅 18/18，另 5 项目录 after 原件未保留 |
| 原版真实 MCP/Evidence 与唯一 live cancellation | `1a1b22b8655-fc05-7cc4` | exit 0；完整13-record bundle、显式新会话 import、分层回读及一次取消观察均保留 |

Native 的 8 次原 job 读取是只读；其余 5 次是相同原请求和 key 的负例 `rea_static_start` 重发，不能称为只读。实际未出现新 job，完整拒绝结果及 registry 原帧仍保留。5 项目录比较只有 producer 布尔，独立资格明确保留 OPEN；后续 R4 采集器只修复未来原件留存，不补写 C9。

三个原版会话与一个 native 补采会话共保留 124 个原始 frame、51 个有结果的业务调用，以及一个没有响应的原版取消请求。完整 CallToolResult、structuredContent、opaque text 和压缩原始 JSON-RPC 各自保留，不用解析文本替代原文。

## 完整结果与共同字段

11 组声明的跨实现完整 CallToolResult 全部 **DIFF**；11 组 opaque text 和原始 RPC frame 也全部 **DIFF**。Native Provider 包装、durable job 字段和 bounded report 与原版完整 Evidence 不是同一结果层。C9 没有在原分析 controller 中采到 native 同层完整 bundle，因此该项是 **尚未采样的缺项**，不能据此断言整个 native capability 永远不存在。

共同字段中，15 个函数（13 internal、2 external）按地址匹配的 address/name/external/thunk 四字段为 60/60 一致。当前 runtime 清单不含原版 symbol 元数据或 thunk target；历史 Java 诊断的六字段投影不是这个 runtime 结果。Entry/interior 两个选择器的完整 C 文本均为相同 63 B，SHA `f5cfb8e45b727b130ef92c6511118695d2454bf9be1b340c66170611d125d029`。

C9 的真实 xref 差异包括：incoming 原版 3 行、native 4 行，额外合成 Entry Point 且其余顺序不同；outgoing 原版 `stack:0xfffffffffffffff4`，native `Stack[-0xc]`。固定原版源码还明确 body+entry 遍历、过滤、去重和排序，C9 native incoming 仅枚举入口。后续补丁会单独验证，不能抹掉本基线失败。

原版 selected function 的 locals、basicblock_count、symbol、thunk_target，以及引用中 source/target procedure、扩展 kind 和 provenance 等缺项逐字段保留。完整 Evidence 的 identity、authority、confidence、environment、locations、relationships、links 与错误恢复元数据未被伪造为 native 等价项。

主派生 `c9-full-result-diff-r1/` 包含 7,954 条完整 typed 字段记录；独立 `peer-derived-c9-r1/` 使用另一 reader 从 raw wire 重新定位字节区间，保留 1,263 条完整结果终端字段差异。两者展开层级不同，行数不是资格分数。所有原文和 opaque 字符串未截短。

## 原版自身的七项回读：值与原文必须区分

原版完整导出为 64,297 B，13 records，SHA `fa5884427caa3bb8f3effef348f04bc23dccc6d187fd4bb50797f17f4cc57dbd`。七项内部检查在各自定义的解析值／谓词层通过，**不代表七项原文字节等价**。

| 检查 | 解析值／谓词 | 完整结果／opaque | RPC 原字节 |
| --- | --- | --- | --- |
| 相同 retained page 再读 | 相等 | 相等 | 不同，实际 ID 不同 |
| export 与完整 bundle | 相等 | export 与实际 bundle member 原字节不同 | 不适用 |
| export 前后完整 bundle | 相等 | 相等 | 不同，实际 ID 不同 |
| 新会话无隐式 retention | 七个 bundle 列表为空 | 不适用 | 不适用 |
| explicit import 后完整 bundle | 相等 | **不同** | 不同 |
| import 后 bundle 与 export | 相等 | export 与实际 bundle member 原字节不同 | 不适用 |
| import 后 retained page | 相等 | 相等 | 不同，实际 ID 不同 |

Import 前后 opaque 文本都有 64,308 B，首次差异在零起始 byte 1,040：view 对象成员次序从 `kind,offset,limit` 变为 `kind,limit,offset`，全 bundle 共 226 处对象顺序变化。两边按类型敏感解析值相等，但原文仍为 DIFF。独立报告保留全部成员顺序变化及完整双方文本；没有用排序后的替代文本宣称原文相同。历史主派生 README 的“exact explicit import/readback”仅指其声明的解析值比较，本分层结论明确限定该措辞。

## 取消与资源归属

只运行了一次原版 active cancellation：观测私有 Java 及其 live native decompiler 后，对原始 request ID 5 发出一条取消通知。完整 close/drain 后没有该 ID 的成功或其他响应，前后 retained bundle 相同，随后会话可查询并正常关闭。结论是 `OBSERVED_LIVE_CANCEL_NOTIFICATION_WITH_NO_COMPLETED_RESULT_AND_RECOVERY`；不宣称因果证明或 native durable-job 语义等价。

四个完整受记录的 capture owner 均正常关闭，无 forced fallback；68 个采样后代均退出。独立只读 census 核查 81 个既往 PID/start 身份及确切自有 unit cgroup：原身份全部消失或被复用、当前无匹配进程、无观察错误、未发送 signal。C9 full harness 的另五个旧 controller 使用会在 5 秒后强制 kill 却不留标记的 legacy close helper；历史是否触发 fallback **未记录**，不能由后来空 census 补证“全部正常关闭”。这些观察也不构成完整进程出生史。

## 档案入口与边界

`c9-mcp-evidence-manifest.json` 逐文件绑定此包全部原字节；三次执行的原始 tool 回执、C9 源快照、完整 wire、exports、输入、stderr、原版固定源片段、R3 driver 历史、主派生及独立 peer 派生一并保留。`c9-packaging-history-r1.json` 保留第一次归档在 8 MiB 单文件限制下拒绝 11,382,504 B catalog 的失败；之后仅归档上限按实测调至 16 MiB，不重跑任何 runtime 或引擎。

包中不包含 51 MiB runtime 二进制或安装后的 Ghidra/JDK/npm 依赖树；它们的固定身份保留在回执中。完整生成输入和 raw frames 足以离线重算本次比较。该档案不会把全部操作资格从 0/229 升级，也不覆盖其他架构、平台、引擎或部署资格。

## 可直接读取的索引

- [完整原件与全部派生归档](raw-evidence.tar.gz)，SHA `65cf5baa813d879ca5d65ecb68c14486a0ba8912373992d119d82fe9c78275e9`，5,143,132 B。
- [逐成员原件 manifest](raw-manifest.json) 与 [归档字节复验回执](archive-verification.json)。
- [主完整结果摘要](comparison-summary.json) 与 [完整 typed 字段 ledger](complete-field-differences.jsonl.gz)。摘要的原版 roundtrip differences=0 只针对其定义的解析值层；以下独立分层表保留原文差异。
- [独立审查说明](peer-README.md)、[独立摘要](peer-summary.json)、[独立文件 manifest](peer-manifest.json) 和 [完整 CallToolResult 差异](peer-complete-calltoolresult-differences.jsonl.gz)。
- [原版七项回读分层表](original-readback-layer-summary.json) 与 [完整分层细节及成员顺序诊断](original-readback-layers.json)。

这些可读副本与归档中的相应原件逐字节一致；README 是原始归档索引的引用版。`documents-manifest.json` 绑定本目录的文件，完整执行及 derived 原路径仍保留在 raw archive 中。
