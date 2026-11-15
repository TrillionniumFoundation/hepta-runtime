# pocket4 权威财务源回放阻塞：只读定位报告

## 结论与范围

**HOLD：当前阻塞来自权威财务事件源缺少一条已提交命令的成交或零成交终态证明，尚不能评价任何权重补丁的真实财务收益。** 本次未证明模型权重有缺陷，也未证明14条历史命令或相应交易数据全部丢失。

2026-11-04 03:11:34.608 UTC 的纯只读回放，在 `scripts/hepta_pnl_accounting.py` 第588行触发 `EvidenceError: SUBMITTED_COMMAND_WITHOUT_FILL_OR_ZERO_FILL_PROOF`。异常帧中的实际 `sent` 命令已与原始日志逐事件对齐，确认该命令的 `fill_count=0`、`terminal_status_count=0`。仅有5条匹配事件：意图、发送尝试、broker本地接受、已发送、PreSubmitted。具体command、订单号、数量、价格及回调epoch放在独立的私有文件，不纳入此聚合报告。

这是**当前日志没有足够证据**的结论。本次没有查询broker当前状态，不能推断订单实际未成交、已取消或实际丢失。

## 可核验的源身份

| 字段 | 结果 |
|---|---|
| 当前日志字节数 | 53,087,317 |
| 当前事件数 | 47,513 |
| 当前日志SHA256 | `c715eea9719a37ec875c4fa877e37c82d8fbcb13d29d5e988006e2c8f30fd573` |
| 未提交尾部字节 | 0 |
| 文件权限/属主校验 | 0600；uid与执行euid均为1000 |
| 64MiB读取边界 | 未超出 |
| 最后已记录回调时间 | 2026-11-03 22:32:02.709 UTC |
| 该回调状态 | PreSubmitted |
| 严格回放最新保留命令分母 | 14；当前完整分母未知 |
| 严格回放当前可授予的observed信用 | 0；14条记录均为CENSORED |
| 最近完整快照 | 2026-11-03 22:31:11.611 UTC；13命令、10 observed |

源文件完整哈希与代码哈希记录在 `aggregate_diagnostic.json`。这些值只是本次读取时的身份；源仍为运行中系统使用的文件，后续观测必须重新记录身份。

## 失效传播链

1. 原始journal仍存在且可解析；未发现本次错误由权限、文件大小边界或不完整尾行造成。
2. 原生财务 `replay` 对每个已发送命令检查成交及终态。当前命令无成交且无可接受的零成交终态，所以严格守卫拒绝生成完整账本。
3. `resident_rewards.current` 捕获该异常，保留在 `components.EUR.USD.reason` 中，并设置 `ledger_complete=false`。
4. `current100k_weight_shadow_eval.py` 第137–138行只追加 `CURRENT_LEDGER_REPLAY_UNAVAILABLE`，未把具体上游原因带入assessment。
5. strict review第217–218行进一步用通用 `STRICT_SOURCE_REPLAY_INCOMPLETE` 生成不可用报告。已有14条命令被保留并撤回当期评价信用；这不等同于确认14条源记录全部丢失。

`TRAINING_LABEL_REVOKED_OR_CHANGED` 是当前源不能完成验证时的上层结果。本次没有证据证明冻结训练标签内容被篡改。不能把“现在无法验证”改写成“全部标签实际改变”。

## 对权重空间研究的影响

当前首先需要真实源证据恢复或独立只读核对，才可能解除财务验收HOLD。改变网络权重不能补全broker的原始经济事件。剔除该命令、假定零成交、改小分母、退回历史快照或放宽守卫都会改变证据意义；本次没有进行这些动作。

冻结的前瞻窗口尚未结束，且现有样本支持有限。即使源证据之后恢复，仍须按原冻结规则等待样本、时间分半、成本与时间外检验；不得将恢复回放直接宣布为模型性能提升。

## 本地建议补丁

`preserve-ledger-replay-reason.patch` 是**未应用、未部署**的最小Python可观测性修复建议。它只为现有 `CURRENT_LEDGER_REPLAY_UNAVAILABLE` issue添加instrument和最多2,000字符的 `upstream_reason`，优先使用component原因；外层源读取失败时退回顶层原因。

补丁不修改任何接受条件、财务逻辑、终态、冻结计划、交易授权或训练权重。它不恢复缺失证据，也不会改变CENSORED计数或HOLD结论。局部控制流检查覆盖：正常完整账本、component明确失败、顶层读取失败、未知原因、消息长度边界；未执行全仓集成测试。

应用前应核对原始文件SHA256为 `5395b81661b11db331f16557c405b5c7aab902c29e6d24574fc03ec63c752de4`，并在隔离checkout执行 `git apply --check` 与现有strict-review回归。此补丁没有被发送至远端代码目录或生产服务。

## 只读执行记录

所有读取使用显式的pocket4主机、/usr/bin/python3、nice=10、CPU上限25%。纯财务回放未加载模型、未请求GPU；记录具体reason的一次回放耗时3.904秒。用于提取异常命令的后续回放同样只读，不改变源目录或评估器状态；禁止Python bytecode写入。

- 上游原因回放job：`1a1a4876fb0-96a-7b7e`。
- 确认异常帧及原始事件的job：`1a1a48a55a0-96a-7b8d`。
- 原始command与事件：`private/command_evidence.json`，私有资料，不应进入公开仓库。
- 可分享聚合结果：`aggregate_diagnostic.json`。

本次没有补造zero-fill、重写journal、修改源评估器、冻结计划或运行中权重，也没有发送任何broker订单。
