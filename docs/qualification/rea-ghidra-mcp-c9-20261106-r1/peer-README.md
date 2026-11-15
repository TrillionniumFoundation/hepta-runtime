# C9 Ghidra：独立完整结果与回读层级复核

本目录复核候选 `c9c79e27a2bf56bd204df6591ca2311dc872e317` 已保存的真实 MCP 原件。原始 capture、wire、结果文本和导出文件未修改。复核脚本只使用 Python 标准库与本目录中固定 SHA 的独立 reader，没有导入当前仓库或启动 REA、Ghidra、JVM、分析任务。本目录的 `qualified` 和完整上游等价标记均为 `false`。

## 入口与方法

固定原版 capture SHA 为 `2981ca455fbb9f64c0d7a7917afc79a34e869f05c5b6d5f7f1c5ea8be937fb82`；native readback capture SHA 为 `5355fd59368b14fe80846f457bad0e4aee857ba3ae02dbe84d2194c9f95937dd`。所有实际引用输入及前后哈希在 `authenticated-inputs.json`。

`derive_c9_peer_r3.py` 从完整 wire index 逐条解压原始单行 JSON-RPC，限制解压大小，核对 gzip/raw SHA、请求 ID、工具名、参数、原始请求顺序及响应。完整 CallToolResult 和 structuredContent 的字节区间由独立 JSON 成员定位重新确定，再核对保存的原始切片。`content.text` 始终作为不透明字符串参与完整结果比较；单独解析文本仅用于明确标记的值层、Provider 观察和成员顺序诊断。

原版的三个 capture owner 与 native readback 的一个 owner 共保留 124 个 frame、51 个有结果的业务调用。四份正常退出回执的原件均已绑定；原版取消请求另有一个未收到响应的 ID 5。这些关闭记录只覆盖四个 capture client，不能补写 C9 旧 full harness controller 的关闭证明。

最终主审计 job 为 `1a1b257ba27-fc05-7d9e`，实际 exit 0；脚本 SHA 为 `e6ec1f42b8f398adbf9ad59fecb000507c4ed679f2d4d20326a21e5c61078bb8`。r1/r2 是在产生 assessment 前停止的离线 reader 迭代，保留原脚本和失败 job；不属于 runtime 验收结果。

## 跨实现结果

`summary.json` SHA 为 `0e38c8843e5c7b25fba81520d65a003f9a536c4d7f39a160ed480e222e4f7827`。

- 11 组对应操作的完整 CallToolResult、不透明 content 和完整 RPC frame 全部不同。对应 native 接口提供持久任务与 Provider 报告包装，未提供同层完整上游 Evidence。RPC frame 对比保留真实 ID 和不同接口的外层差异。
- `complete-calltoolresult-differences.jsonl.gz` 保存完整 typed 差分，共 1,263 个终端字段差异。缺失的对象按全部终端字段展开；不透明文本保持一个完整字符串，不拆成解析后的成员。因此此行数不等于其他采用不同展开层级的诊断行数。
- 固定 ELF 两份实际输入逐字节相同：15,680 B，SHA `ec301f409d22314b43b4392fa80ada28213cd75ca77c6cbbbbfe1454555dd64a`。
- 按地址匹配的 15 行（13 internal、2 external）在 address/name/external/thunk 四字段上相同。原版 symbol 和 thunk_target 没有对应的 native 行字段；原版与 native 数组布局也不同。
- entry/interior 两个选择器的 C 文本均为完全相同的 63 B，SHA `f5cfb8e45b727b130ef92c6511118695d2454bf9be1b340c66170611d125d029`。这项观察不覆盖整个 Evidence。
- native-only 复算有 18 个相等事实：8 个实际保留报告、5 个完整错误 CallToolResult、5 次实际 process_list 的 job ID 集合。另 5 个目录 after 快照没有单独保留，不能把 producer 自报的 23 个布尔全部称为独立重放通过。

完整 selected 对照见 `selected-observation-comparisons.json`。native selected function 缺少原版 locals、basicblock_count、symbol 和 thunk_target。引用结果缺少原版相关 source/target procedure 和多个 reference kind 字段。

两类直接可修复的 C9 xref 差异均同时出现在 entry 与 interior 请求：incoming 原版 3 行、native 4 行，额外行是合成 Entry Point；剩余 3 行的顺序也不同。outgoing 两行的目标地址，原版为 `stack:0xfffffffffffffff4`，native 为 `Stack[-0xc]`。原件与失败均保留，本目录不把后续修复反写进 C9 结果。

## 原版七项内部回读的比较层级

完整分层数据在 `original-roundtrip-comparison-layers.json`，SHA `003308091a9fcb1a2ae1c48af1832627194968d50f435e4dc58c651066c16809`。便于浏览的表在 `original-roundtrip-layer-summary.json`，SHA `8ad64fba6e61ad4613cb21db79ca4df3021f55bef8c8dac003ef592c4f7cc796`。补充派生 job 为 `1a1b25e49b5-fc05-7dbb`。

“完整结果”在这里指保留 opaque text 的 CallToolResult；“值”使用类型敏感比较。N/A 表示该项没有对应的第二份结果、frame 或导出，不能当作通过。

| 原版检查 | 解析值／谓词 | 完整结果 | opaque text | 结果原字节 | RPC 原字节 | 导出与实际 bundle member 原字节 |
| --- | --- | --- | --- | --- | --- | --- |
| 相同 retained page 重读 | 相等 | 相等 | 相等 | 相等 | 不同，实际 ID 不同 | N/A |
| export 与 complete bundle | 相等 | N/A | N/A | N/A | N/A | 不同 |
| export 前后 complete bundle | 相等 | 相等 | 相等 | 相等 | 不同，实际 ID 不同 | N/A |
| 新会话没有隐式 retention | records 为空；七个 bundle 列表均为 0 | N/A | N/A | N/A | N/A | N/A |
| explicit import 后完整 bundle | 相等 | 不同 | 不同 | 不同 | 不同 | N/A |
| import 后 bundle 与 export | 相等 | N/A | N/A | N/A | N/A | 不同 |
| import 后 retained page | 相等 | 相等 | 相等 | 相等 | 不同，实际 ID 不同 | N/A |

完整 bundle 共 13 条 records。冷启动导入前后的 opaque text 都是 64,308 B，首差在零起始 byte 1,040：`$.result.records[0].parameters.view` 的成员顺序由 `kind,offset,limit` 变成 `kind,limit,offset`。整份文本有 226 处对象成员顺序变化。完整结果都是 134,393 B，首差在 byte 1,271；完整 RPC 的首差在 byte 1,281，之后还有真实 ID 22→5 的差异。

两边的解析 payload、structuredContent 和元数据分别按类型敏感比较相同；两份文本各自精确等于其自身成员顺序的 compact JSON。两边的 bundle 值按排序成员的 compact 编码都精确等于实际 64,297 B 导出文件，SHA `fa5884427caa3bb8f3effef348f04bc23dccc6d187fd4bb50797f17f4cc57dbd`。这些诊断将差异定位到成员顺序；实际 opaque/text/frame 比较仍保留为不同。

导出文件与 before/after 实际 bundle member 的首差均在 byte 16。before member SHA 为 `031a56be48ed094d195b8f18dba535a9e1144bacdcbca2c93f46922374944d85`，after 为 `a093cba9a97a044c205c0b00f2c09ab0919d59c75a78f38165e478c550e59f5f`。两个 member 均为 64,297 B，但都不是导出文件原字节。

`original-roundtrip-complete-differences.jsonl.gz` 保留唯一发生变化的完整 opaque 字段及双方原文，不截短、不排序后替换原值。补充比较也由另一审查者独立读原件核实（只读 jobs `1a1b25b668d-fc05-7dad`、`1a1b25c3762-fc05-7db0`）。

## 尚未据此关闭的门槛

本目录不提供 native 同层完整 Evidence、bundle、export/import 的资格，不证明所有错误、期限、因果取消、断连恢复、平台、发布成本或全部操作等价。比较结果不会把 0/229 操作资格升级。原版自身的七项 parsed 内部回读观察也不能替代跨实现结果或原文字节等价。
