# Hepta Colab adapter — scoped profiles v4

这个目录把聊天侧的 Hepta `process_start/status/read` 接到 Google 官方 `google-colab-cli` Python SDK。适配器提交有限时长的 Python 脚本，把执行身份、完成证据和原始产物保存到 SQLite 及文件。每个 profile 固定一个已经分配的 Colab runtime、专属 kernel 和 Jupyter client session；管理客户端负责授权、资源资格查询及创建专属 kernel。

代码与本地故障测试完成，不等于 Google 云端验收完成。只有真实授权账号下取得的 runtime、计算回执、下载文件及取消观察才能勾选云端工作包。

## 显式授权与 SDK 边界

`~/.local/bin/hepta-colab-authorize` 现默认使用官方 google-auth-oauthlib 的
loopback + PKCE 回调，仅监听 `127.0.0.1` 临时端口，不再要求复制一次性授权码。
浏览器收到回调不代表凭据已保存；以私有 auth-status.json 的 authorized、
账号/权限校验和 OS keyring 持久化验证为准。后台 non-interactive 调用仍不启动授权。
旧手工模式保留供直接调用 helper 时使用。原 SDK 固定提交未修改。

管理客户端支持全局参数 `--quota-project PROJECT_ID`，仅为公共 REST 查询显式
指定 `x-goog-user-project`；未指定时兼容旧行为。Google Cloud SDK 的内置 OAuth
client 所属项目不等于用户项目。公共接口返回 `PUBLIC_API_SERVICE_DISABLED`
时，需先选定用户有权使用的项目并启用 `colaboratory.googleapis.com`；这不是
刷新 token 或重复 OAuth 能解决的问题。此补丁不会自行启用 API 或创建资源。

## 上游依据及版本

核心依赖使用 Google 官方仓库固定提交 [`d2d97794941723ab806c0f3642416691a951ec7d`](https://github.com/googlecolab/google-colab-cli/tree/d2d97794941723ab806c0f3642416691a951ec7d)，其 `pyproject.toml` 要求 Python ≥3.12，pip 依赖固定 `jupyter-kernel-client==0.9.0`。Google 开发环境的 uv 配置另有 fork 覆盖，不能把 fork 的版本与 pip 锁定混装。

- [`runtime.py`](https://github.com/googlecolab/google-colab-cli/blob/d2d97794941723ab806c0f3642416691a951ec7d/src/colab_cli/runtime.py)：`ColabRuntime(..., kernel_id=..., session_id=...)` 连接既有 kernel；`execute_code` 每次发送新的 Jupyter execute 请求；`stop(shutdown_kernel=False)` 只关闭客户端连接。
- [`contents.py`](https://github.com/googlecolab/google-colab-cli/blob/d2d97794941723ab806c0f3642416691a951ec7d/src/colab_cli/contents.py)：`ContentsClient` 提供上传、下载与目录读取。
- [`client.py`](https://github.com/googlecolab/google-colab-cli/blob/d2d97794941723ab806c0f3642416691a951ec7d/src/colab_cli/client.py)：官方 assignments、CCU、资源分配及代理 token 刷新。
- [`auth.py`](https://github.com/googlecolab/google-colab-cli/blob/d2d97794941723ab806c0f3642416691a951ec7d/src/colab_cli/auth.py)：官方 OS keyring OAuth 凭据格式与刷新路径。

适配器直接导入 SDK，跳过 `colab.cli` callback。该提交的 `setup_logging` 会把 DEBUG 请求头/响应写入本地日志，可能包含访问 token；本适配器在 SDK 边界禁用上游日志，异常只返回固定错误码或异常类型。`ContentsClient` 的唯一传输扩展是增加连接/读取 timeout 与流式响应大小上限，URL 与参数严格沿用上述源代码。

## 文件及边界

| 文件 | 职责 |
|---|---|
| `hepta_colab.py` | Profile、SQLite ledger、SDK provider、submit/run/status/read/cancel/fetch CLI |
| `remote_runner.py` | 在固定云端 kernel 中启动有限 Python 子进程，保存原始输出、回执及产物清单 |
| `authorize_colab.py` | 独立安全授权流程，由管理客户端明确启动 |
| `manage_colab.py` | 账号/额度/资源规格与专属 kernel 的管理客户端（若部署包提供） |
| `account_launcher.py` | 按私有配置选择账号和独立 profile，不允许尾随参数覆盖身份 |
| `launch_authorization.py` | 显式授权启动辅助入口 |
| `test_scoped_profiles.py`、`test_cleanup_unstarted.py`、`test_bind_ledger.py` | 31 项离线故障回归 |

适配器运行 Python **脚本任务**。用户代码由固定 kernel 启动的 Python 子进程执行，工作目录为该 job 的 `work/`；不会继承 notebook 的 Python 变量。这个选择让 stdout/stderr 能作为真实二进制文件留存，并且取消能够只终止当前 job 的进程组。需要 notebook 内存状态的任务应另外定义对应合同。

## Scoped profiles v4 与未派发清理

`account_launcher.py` 从当前用户的私有 `accounts.json` 选择账号，隔离
keyring、bootstrap、jobs ledger 与 profile。实际账号不会写入发布源码。
所有尾随身份、状态目录或 profile 覆盖参数继续被拒绝。

```text
hepta-colab-account ALIAS manage readiness
hepta-colab-account ALIAS manage create --key KEY --kind gpu --accelerator T4 --shape standard
hepta-colab-account ALIAS --provision-key KEY manage bind --key KEY
hepta-colab-account ALIAS --provision-key KEY run submit --key KEY --code-file /absolute/task.py --wall-seconds 120 --artifact result.json
hepta-colab-account ALIAS --provision-key KEY run inspect-key --key KEY
hepta-colab-account ALIAS manage close-unstarted --key KEY
```

请以实际 `--help` 核对 create 参数。`readiness` 仅查询授权与账本，返回
`can_create`、`job_profile_supported` 及 `allocation_blockers`。未决 allocation
或 release 阻塞新资源申请；eligible 不代表分配成功。只有官方 HTTP 412
明确拒绝才记为 `allocation_refused`；超时等不确定结果仍保持 unknown。

`--provision-key` 必须位于 action 之前。profile 路径由同账号的 provisioning
key 派生，绑定原账号、endpoint、kernel、client session 和 profile 摘要；
不能通过该参数接管其他 runtime。v4 在首次 kernel 写请求及暴露绑定 profile
之前初始化固定 jobs ledger。已绑定任务的 ledger 若丢失，禁止重新建空账本。

`inspect-key` 是原账号账本的本地查询。找到任务时返回原 job、源码摘要、时限、
声明产物和 runner 校验证据；未找到时区分账本存在且确认无记录、账本缺失。
仅相同提交意图可恢复原 job。已释放 profile 仍可读取保留且校验过的结果。

`close-unstarted` 仅关闭原账本在同一锁内证明从未 dispatch 的自有 runtime。
queued job 须先得到本地取消回执。已 dispatch、active、unknown、foreign/busy
kernel、身份冲突或缺失证据都拒绝清理。结果保留 `never_dispatched=true`、
`cleanup_reason=unstarted_compute` 和原始证明；未知释放只 reconcile，不重发。
这条路径不代表计算成功，也不会丢弃已经执行任务的唯一输出。

## Profile 与准备条件

Profile 不含密码、访问 token 或代理 token。示例中的身份值必须来自实际会话：

```json
{
  "name": "rog-colab",
  "session_name": "hepta-colab-owned",
  "state_file": "/home/operator/.local/state/hepta-colab/bootstrap/credentials/sessions.json",
  "endpoint": "ACTUAL_RUNTIME_ENDPOINT",
  "kernel_id": "ACTUAL_DEDICATED_KERNEL_ID",
  "session_id": "ACTUAL_JUPYTER_CLIENT_SESSION_ID",
  "remote_root": "/content/hepta_jobs",
  "max_wall_seconds": 600,
  "max_artifact_bytes": 33554432,
  "max_output_bytes": 8388608,
  "auth_provider": "oauth2",
  "expected_account_email": "VERIFIED_ACCOUNT_EMAIL"
}
```

`state_file` 是官方 `StateStore` 格式，包含敏感代理凭据，应位于用户私有目录并限制为本人访问。生产 profile 必须含有非空的 `expected_account_email`；provider 在使用代理前通过 Google 官方 tokeninfo 校验 OAuth 账号。只有离线注入的模拟 provider 可省略该字段。浏览器已经登录 Google 不等于 OS keyring 已经授予 CLI OAuth；缺少可刷新凭据时返回 `AuthRequired`，不会隐式弹出登录或读取浏览器 cookie。

`bind` 可以从含有 kernel/session IDs 的现有 `StateStore` 生成 profile；它不会新建 runtime 或 kernel：

```bash
python hepta_colab.py \
  --profile /home/operator/.config/hepta-colab/profile.json \
  --state-dir /home/operator/.local/state/hepta-colab/jobs \
  bind --session-name hepta-colab-owned \
  --session-state-file /home/operator/.local/state/hepta-colab/bootstrap/credentials/sessions.json \
  --expected-email VERIFIED_ACCOUNT_EMAIL
```

`profile.example.json` 仅说明字段，不能用于实测。实际 profile 由 `manage_colab.py bind` 核实账号、runtime 和专属 kernel 后生成；该管理命令应显式使用 `--jobs-state-dir /home/operator/.local/state/hepta-colab/jobs`，并将管理状态放在 `/home/operator/.local/state/hepta-colab/bootstrap`。上面的 adapter `bind` 仅适用于已经存在、已有固定 kernel/session 身份的 session store。

profile 写入采用不覆盖已有不同内容的方式。重新选用另一 runtime/kernel，应建立明确的新 profile，既有 job 保持原身份。请勿把未完成 job 偷换到新 runtime。

## 操作合同

全部 CLI 正常结果为 JSON，错误仅输出 `{error, code}`，退出码 2。所有命令都有 `--profile` 与 `--state-dir` 两个全局参数。下面以 `$PYTHON`、`$ADAPTER`、`$PROFILE`、`$STATE` 表示部署路径，其中 `$STATE=/home/operator/.local/state/hepta-colab/jobs`；通过 Hepta 调用时传递真实绝对路径及 argv，不需要 shell 展开。

### 提交与运行

```bash
$PYTHON $ADAPTER --profile $PROFILE --state-dir $STATE \
  submit --key colab-acceptance-compute-001 --code-file /absolute/path/task.py \
  --artifact result.json --wall-seconds 300
```

`submit` 只建立持久 job，返回 `job_id`。提交键最长 128 字节；代码最长 256 KiB；产物最多 32 个且必须是严格相对路径；`stdout`、`stderr` 为保留名。相同 key 和相同 payload 返回原 job；改动代码、产物合同、profile、时限或 runner 版本会拒绝该 key。

接着把 `run` 交给 Hepta 持久进程：

```json
{
  "host": "rog",
  "executable": "/absolute/release/venv/bin/python",
  "args": [
    "/absolute/release/hepta_colab.py",
    "--profile", "/home/operator/.config/hepta-colab/profile.json",
    "--state-dir", "/home/operator/.local/state/hepta-colab/jobs",
    "run", "--job-id", "RETURNED_ADAPTER_JOB_ID"
  ],
  "idempotency_key": "hepta-run-RETURNED_ADAPTER_JOB_ID",
  "timeout_seconds": 720
}
```

Hepta 返回的 `job_id` 是 ROG 上的进程身份。适配器 JSON 内 `job_id` 是云任务身份。`endpoint`、`kernel_id`、`session_id` 是固定云端身份，四者不能互换。Hepta 查询本地进程结束不能单独证明云任务结束；以适配器的 `cloud_receipt` 为准。

`run` 在数据库事务中把 `submit_attempts` 从 0 改为 1，然后才发送一次用户计算。并发重复 `run` 只能有一个胜者。一次发送之后，不管发生超时、连接中断、客户端退出还是结果丢失，后续 `run` 都只查询原 job，不重发计算。

### 查询及断线恢复

```bash
$PYTHON $ADAPTER --profile $PROFILE --state-dir $STATE status --job-id JOB_ID
$PYTHON $ADAPTER --profile $PROFILE --state-dir $STATE status --job-id JOB_ID --local
```

默认从固定云 runtime 的原 job 目录读取 `status.json`；`--local` 只读持久 ledger。状态可能为 `queued`、`dispatched`、`running`、`cancel_requested`、`unknown`、`succeeded`、`failed`、`cancelled`、`timed_out`。

`unknown` 表示发送或观察结果不确定，不能据此推出未执行。只有官方 Contents API 的原始云回执可以恢复状态；缺少回执时保持 unknown，不另起任务。同一 endpoint/kernel 有 queued、running、cancel_requested、dispatched 或 unknown 时，会拒绝其他新 job，防止取消及恢复指向错误工作。

每份回执必须匹配 job、payload hash、runtime endpoint、kernel ID、client session ID。已保存的终态不能被稍后的旧 running 回执覆盖。`cloud_observation=fresh` 说明本次读取通过；`retained` 说明展示的是之前已验证证据，并带有本次 `refresh_error` 类型。保存下来的历史完成事实不等于云 runtime 目前仍然在线。

CLI 的 Jupyter 协议没有“用同一个 execute_code 自动续传”保证。本适配器通过读同一目录、同一回执和同一输出文件恢复观察。远端还有原子目录 claim，意外重复收到同一包装请求也不会再次启动用户脚本。

### 原始输出和产物

```bash
$PYTHON $ADAPTER --profile $PROFILE --state-dir $STATE \
  read --job-id JOB_ID --stream stdout --offset 0 --limit 16384
$PYTHON $ADAPTER --profile $PROFILE --state-dir $STATE \
  fetch --job-id JOB_ID --artifact result.json --destination /absolute/results/result.json
```

`read` 返回字节 offset、next_offset、base64、该片段 SHA-256 与便于查看的 UTF-8 文本。base64 是原始字节依据；文本替换无法解码字符不会改变原始字节。运行时输出为瞬时快照；终态输出必须与云端清单的完整大小和 SHA-256 一致才标记 verified。

脚本在 `work/` 内写入约定的产物。云端先哈希文件并写入 `artifacts.json`，再把清单自身 SHA-256 写入终态回执。适配器核对这条链后下载真实字节，同时验证大小和内容哈希。收到终态时尽早把 stdout/stderr 及声明的产物保存到本地私有缓存；某一文件缓存失败不把已观察的计算完成改写为失败，后续 fetch 可以重取。

本地下载使用逐级 `O_NOFOLLOW` 打开目录、独占临时文件及原子无覆盖发布。已有同内容文件可复用，已有不同内容或符号链接被拒绝。文件父目录需预先存在。恢复已缓存、已验证的产物无需再连云端；云 VM 删除前尚未取得的文件无法凭本地回执重建。

### 取消

```bash
$PYTHON $ADAPTER --profile $PROFILE --state-dir $STATE cancel --job-id JOB_ID
```

queued job 可在发送前取消，并明确标记 `local_only_cancel=true`。已发送任务的取消会通过官方 Contents API 写入同 job 的取消标记。云 supervisor 持续处理真实任务控制，观察到匹配标记后对本 job 子进程组发 TERM，等待、必要时 KILL，并确认子进程已回收且进程组无活动计算，最后写出取消回执。

取消意图先持久化，再尝试凭据和网络操作。如果第一次取消发生在云端 job 目录创建之前，或网络暂时不可用，后续 status / 原 worker 会为同一 job 补交同一不可变取消标记；这不会重发计算。

`cancel_requested` 只是请求，只有匹配的云回执 `state=cancelled`、`cloud_execution_stopped=true` 且 `cloud_process_group_alive=false` 才构成云端停止证据。若任务先成功，返回 succeeded；不会改造为 cancelled。请用 status 继续观察。结束 ROG 本地 Hepta worker 或断开 websocket 不会被当作取消成功。

进程组确认先使用当前 PID namespace 的 `killpg(..., 0)`；只有 `/proc` 对应同一 namespace 时才用它区分 zombie。无法确认的状态保持 unknown。该合同覆盖正常子进程树，刻意另建 session、逃离进程组的程序不属于这一有限脚本适配器的隔离保证。

## 保留与限制

- SQLite 使用 WAL、FULL synchronous、事务和唯一键。数据库及缓存目录为当前用户私有。凭据不写进 ledger；提交代码、业务输出和产物按任务要求保留。
- 云端每任务 wall time 最长由 profile 限制；默认 600 秒。日志监控默认 8 MiB，文件硬限制默认 32 MiB。SDK 客户端等待稍长于任务时限；仍可能因网络或 Colab 回收而进入 unknown。
- 该实现不会创建额外 GPU、延长服务期限、发送保活空算，也不会自动为 unknown 分配替代 runtime。
- Colab runtime 被回收、删除或重启后，未下载的临时文件和执行状态可能消失。官方消费级 Colab 并不因此变成具有持久 SLA 的作业队列。
- 同一专属 kernel 只允许此 adapter 管理计算。人工向相同 kernel 插入工作会破坏单一所有权假设。
- `status` 与下载不启动 kernel；它们读取官方 Contents API。已有持久取消意图但标记缺失时，status 可向原 job 目录补交该控制文件。创建/选择资源以及验证账号实际规格与配额由管理客户端负责。
- 代理 URL 仅接受 Google 已审查的 HTTPS origin（包含已核对的 `colab.research.google.com`、`*.googleusercontent.com` 及与分配 endpoint 匹配的 `*.prod.r.colab.dev`），禁止 URL 内嵌账号、密码、query、fragment 及非 443 端口。Contents 请求禁止重定向，拒绝非 2xx 响应；若真实分配返回其他 origin，需核实官方来源后再扩展允许范围。
- 后台读取凭据前先检查 OS keyring；SDK 标准输出、标准错误只在内存内捕获，运行日志不会显示代理 token、OAuth 链接或含认证 query 的异常详情。

## 本地验证与云端验收

```bash
python3 -m unittest -v test_scoped_profiles.py test_cleanup_unstarted.py test_bind_ledger.py
python -m py_compile hepta_colab.py remote_runner.py
```

必须单独保留云端证据：账号/资格返回值、真实分配规格、固定 session ID、计算结果及 hash、下载后本地 hash、断线前后相同 job 身份和一次提交计数、取消后云进程停止回执。离线故障测试证明代码的控制语义，不能代替这些真实账号结果。
