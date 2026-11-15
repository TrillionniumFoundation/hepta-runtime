# X230 原生多机验收：当前认证阻塞

当前多机验收仍停在 **current-agent 认证前置条件**。这项阻塞不影响本机发布构建、archive 性能比较或 owner 生命周期测试。

## 本轮实际读数与历史读数

父代理已用原 idempotency key 对账，取得 job `1a17637f098-96a-a8f` 的结果。当前 `SSH_AUTH_SOCK` 存在，确实为 Unix socket，权限为 `0600`，设备号／inode 为 `79 / 82`；当前 `ssh-add -l` 返回 **exit 1**。

**本轮没有记录精确 identity count，必须保持为未知。** 这次结果说明尚未建立可用的 agent 身份，不能把 exit 1 转写为“本轮精确测得 0 个 key”。

已有 `current-agent-metadata-diagnostic-r01.json` 的历史诊断记录过 **identity_count = 0**，且 socket 设备号／inode 相同。该历史数值单列保留，不替代本轮缺失的计数。

## 为什么不能直接改用 IdentityFile

对本地保存的 `run_a41_native_validation_r07.py` 的审阅确认：

1. `input_manifest` 要求既有 `hepta-observation-ssh-pool/v1` profile，并校验其 SSH 配置和 known-host 文件的完整摘要。
2. driver 在执行任何 stage 前要求当前 `SSH_AUTH_SOCK` 指向真实 socket，并记录其文件系统身份。
3. 每个 stage 前后及最终检查都会重新核对同一 socket 身份。
4. 继承管道、运行中任务恢复、六主机 file-pool ABBA 与 soak 均沿用这个 profile template。
5. 现有 driver CLI 没有可替代上述绑定的 `IdentityFile` 选项。

因此，即使某个 OpenSSH 连接可以通过合法的 IdentityFile 认证，也不能无声替换为这次既有 profile 的验收依据。认证来源和 profile 绑定会发生变化，需要独立明确的配置／源码身份与重新验收。

这一结论**不等于底层 runtime 或 OpenSSH 普遍不支持 IdentityFile**。driver 自身检查的是 socket 身份；身份枚举由单独的预检／helper 提供。本次本地目录没有完整 `resume_native_validation_r07.py` 和 `x230_file_pool_benchmark.py` 副本，未对其全部身份枚举实现作新的独立审阅。

父代理读取的原配置使用六个固定 aliases，保持 `BatchMode yes`、`ConnectTimeout 8`、`ForwardAgent no`、`StrictHostKeyChecking yes`。旧 agent 路径只是历史记录，不用作当前认证来源。

## 可继续执行的正常路线

在既有 operator 会话中恢复已授权、实际可用的当前 agent 身份；随后绑定当前 socket、身份及原 SSH 配置／known-host 摘要，建立 fresh profile，再执行原有有界多机验收。**本报告没有宣称上述恢复已经完成。**

本机 archive benchmark 明确不使用 SSH 或 profile，因此本机候选验证继续进行。此次跟进只读本地源码并生成报告，没有搜索或复制私钥，没有改认证配置／服务，没有远端工具调用，也没有尝试用空 socket 或放宽校验来通过预检。

## 证据身份

- 原诊断 idempotency key：`x230-a46-agent-metadata-20261026-multihost-r01`
- 原诊断 job：`1a17637f098-96a-a8f`
- 原始调用文件：`runtime-tools/multihost-diagnostic-request.json`
- 原始调用文件 SHA-256：`a7805d8f340698243d7af494466b40958fee317d4a993d4cdd97951005132783`
- 原 native driver SHA-256：`6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9`

当前远端读数来自父代理已完成的同 key 对账摘要；本子任务没有再次远端执行。

