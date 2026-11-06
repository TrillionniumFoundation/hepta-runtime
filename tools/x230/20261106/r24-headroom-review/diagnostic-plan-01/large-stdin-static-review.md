# 大 stdin 的 launch_unknown：R24 静态路径复核

结论：已核 accepted R24 的 Python launcher 和 system-jobctl 两条路径均将请求 JSON 送到 SSH 的管道 stdin；没有将用户 stdin 另做 base64、拼入 SSH 命令行，或因用户 stdin 增长而扩大 Python -c 源参数。当前掌握的事实不足以定位实际失败，也不足以断言是 argv 上限、64 KiB 管道边界、网络或 helper 故障。当前已安装 controller 的版本未被这份复核验证。

范围：本地只读源码与父任务提供的观察。未访问 x230/Mac，未测 ARG_MAX、未运行 Cargo/formatter/fixture，未修改冻结源码，未重试任何启动效果。以下“实际观察”是 parent-reported，不冒充已读取原 native 回执；其原 job/工具/source SHA 在这份报告里均不可得。

## 父任务报告的实际观察

| 项目 | 已知内容 | 本复核的证据级别 |
|---|---|---|
| 大请求 | process_start(x230) 的 stdin 477,316 B，内含 354,738 B 的 tar base64 文本 | 父任务报告；未取得原完整参数/回执 |
| 返回 | launch_unknown | 同上；不等于已证明未启动 |
| 随后只读观察 | 原 remote jobdir 不存在，ROOT absent，原 unit not-found/MainPID 0/inactive | 父任务报告；未在本复核重新探测 |
| 替代运输 | 同一 tar 经 binary_upload 的 6 个至多 64 KiB 分块及 commit 后，用 5,074 B stdin 的 installer 读取上传文件成功 | 父任务报告；这是不同运输路径，不是单变量对照 |
| API 声明 | stdin 最大 1 MiB；477,316 B 低于该声明 | 工具描述与 R24 MAX_STDIN_BYTES/validate_start 一致；不证明传输链每一层相同版本 |

独立的 absent/unit-not-found 观察有助于原身份对账，但一次终态观察不能据此补造原 launch 的错误原因或完整历史。本报告不以“另一路径成功”推出原路径一定有尺寸阈值。

## 已核 R24 数据流

1. jobs.rs:72、3763–3823：validate_start 检查 params.stdin 的 UTF-8 byte length，超过 1,048,576 才拒绝。它不是字符数限制。该检查只证明 API 参数校验，不保证任意合法参数必能在给定 deadline 下启动。
2. jobs.rs:4192–4236：launch_record 的 request 将 params.stdin 原样作为 JSON 字符串字段，同时保留原 executable/args/env。这里没有 base64 编码。
3. ssh.rs:504–530：python_json_command 仅将 interpreter 与固定 helper code shell_quote 后组成 remote command；serde_json::to_vec(input) 是独立 payload。JSON 转义可能增加线上字节数；实际增量需要原完整参数才能计算。用户在 stdin 内自行放置的 tar base64 不等于 transport 再加一层 base64。
4. ssh.rs:460–473：remote command 进入 SSH argv；payload 进入 stdin_data。ssh_direct.rs:551–575 将 input 复制进有界 admission 下的 Request；320–354 的 capture 并行驱动 stdin.write_all、stdin.shutdown、两个 bounded output reader 与原 owned.wait。这里没有 64 KiB 的输入拒绝条件，也没有固定 64 KiB 分块后不继续写的逻辑。
5. jobs.rs:2664–2670：远端 START_CODE 先 json.load(sys.stdin)，再 private_job_directory(..., create=True)。因此此版本按完整 JSON/EOF 协议读入请求，不能把“本地 write_all 返回”当作远端处理已经完成。
6. jobs.rs:2704–2735：launcher pop 出 stdin 字段，将 UTF-8 字节写入自有 stdin.bin 并同步；request.json 留 stdin_path。2851–2869 的真实 supervisor 打开 stdin.bin，用文件句柄作为 workload stdin。用户 stdin 不在随后 workload 的 argv 中，除非用户自己把大内容另放进 params.args；本次 exact args 未在这里取得。
7. jobs.rs:3323–3367：systemd-run 和 detached fallback 的 Python -c 参数是固定 runner 源，其余绑定为 job_dir/nonce/digest 等身份值；stdin 不在 runner 字符串中。固定 helper/runner 本身仍作为 argv 运行，但其体积不由用户 stdin 决定。
8. 若 record.system_jobctl 为真，ssh.rs:596–615 使用固定命令 sudo -n /usr/local/libexec/hepta-runtime-jobctl，以 JSON 加 LF 写 stdin。此处同样未将 stdin 改成 argv；这份复核没有扩展到未知安装版本的远端 jobctl 内部实现。

另需避免两个误读：ssh.rs:31–43 的 64 KiB 是 observation pool 的 command+query 边界，start 的 direct 路径没有调用该校验；ssh.rs:432–445 的 8 MiB 是 stdout/stderr capture 上限，不是 stdin 上限。声明最大 1 MiB 和固定 deadline 是不同约束。[S2][S3][S6]

## 这里确实有统一 deadline，但不能据此归因

R24 Python launch 与 jobctl launch 都给出 20 s 原 transport 预算；Python 分支在组装 command 与序列化 payload 之前计算 deadline。该预算继续覆盖 direct 的 host/global admission、owner 提交、创建 SSH、pipe I/O、远端处理和原 child 等待，不因较大 stdin 自动增加。publication permit 等外层工作在这个 transport budget 之外，因此整体 tool wall 不必等于 20 s。

write_all 正常应持续等待可写并完成全部字节；源代码看不到“大于 64 KiB 就停止”的分支。但下游读取速度、remote command 早退、BrokenPipe、原 deadline 到期、stop/cancellation、SSH 创建/输出/JSON错误等，都可能使同一 capture 返回 Err。这里只枚举源代码能够合流的类别，不按现象给它们排序；没有实际错误原件就不能称某个原因更可能。

## 为什么 launch_unknown 不足以定位

jobs.rs:4014–4086 的 trusted_launch_ack/preserve_launch_outcome 将无效 ACK 和 Err 合并为 launch_unknown，launch_error 仅保留 Remote launch outcome unavailable。原 error chain、stdout/stderr、失败阶段不进入这个返回结构。该保守行为避免在 ACK 丢失后错误重放远端效果，但也使单个 tool 返回不足以区分 admission、SSH、远端 helper 或 ACK 解析。

若能够证明实际安装代码就是这一版本、原 job_dir 路径/host binding 未变且观察覆盖原 attempt，目录未建立会缩小到 private_job_directory 成功完成之前或该边界本身的失败范围；这些前提当前不齐。此处不把目录 absence 自动转化为“stdin 未传到”、不把 systemd unit-not-found 当成“从未创建”，也不对未知版本作推断。

## 下一步最小证据，不需要重放大请求

- 先取得失败时 installed controller 的可验证 ELF/build identity、对应 source/transport 版本与实际 backend；不能以工作树 HEAD 或本次 R24 审查替代运行中身份。
- 保留原 request identity/key、raw stdin byte length、完整 JSON payload 的长度/哈希、固定 SSH command/runner 的长度/哈希、实际 host alias/target 和原 monotonic elapsed/deadline。诊断长度/哈希即可，不发布 stdin 内容或凭据。
- 优先取原存在的 controller/native/SSH/helper 错误与原 output bytes；若 preserve_launch_outcome 已将底层错误丢弃，明确“无法从现有回执恢复”。不得补写一个猜测的 errno，也不能为获得错误而换 key 重启原效果。
- 原 jobdir/launch/owner/terminal 与 unit 的只读对账继续绑定同一身份和观察时刻。若它们已由 root 取得，复用原件即可；本复核没有要求再次远端探测。
- 只有未来另冻的传输诊断版本才可在不改变错误/重试语义的前提下记录有限阶段错误、输入长度和 read/write 完成点；这不在当前 R35 冻结范围内，也不是本计划的实现请求。

是否触发实际平台 argv 限制，需要运行中版本的真实 exec 参数/环境、平台与原失败 errno 等证据；本地 R24 字节路径本身不能证明这些。没有执行任何 getconf/sysconf/ARG_MAX 尺寸试验；也不建议把观察到的一次失败写成通用最大 stdin 修正。

来源：source-index.json 的 [S2] jobs.rs、[S3] ssh.rs、[S6] ssh_direct.rs，全部匹配 accepted R24 的 220 项 map。当前工具声明只作为接口描述，不作为 installed binary 的版本证明。
