# Compiler metadata preflight：仅准备的 native 请求

状态：**prepared-only，未调用 native、未上传、未启动。** 当前另一 owner 的 reservation23（14:38:37 UTC，R28 full qualification）有效，且该 owner 是唯一 native executor；目前没有 handoff。资格完成后，也可由协调 root 决定让原 owner 执行本包的完全相同请求，避免转交 RPC ownership；当前不自动授权。原 preflight.py、已发布副本、plan/manifest 均逐字保留。

请求 JSON 是工具参数本身，不包含伪造 response/job ID。依次使用对应工具：

1. `01-setup-tools-parent.process_start.request.json`：只新建 `/home/qian/hepta-runtime-optimization-20261105-b96-compiler-preflight-tools-01`，0700，现存即失败，不 chmod、不修复、不另选目录；先确认探针输出目录不存在。该 setup 有自己的唯一固定 key `hepta-x230-b96-compiler-preflight-tools-20261105-01`，15s timeout。等待原 job 强成功 exit0，并保存 stdout 中 fresh/owner/mode 身份后才能继续。
2. `02-stage-preflight.binary_write.request.json`：路径 `/home/qian/hepta-runtime-optimization-20261105-b96-compiler-preflight-tools-01/preflight.py`，`expected_version` **字符串 `"absent"`**，严格 base64 解码 **14763B**，SHA `9995fef189b4a452f7f6a9dca3a2c4b6613517153569b176893d309234aa6c14`。不可覆盖旧文件。
3. `03-verify-preflight.file_info.request.json`：要求同一路径为普通文件、14763B、上述完整 SHA、create-only 文件 mode0600，并保存返回 version。file_info 不能用于目录探测；tools 目录身份来自原 setup 的强终态与 stdout。
4. `04-run-preflight.process_start.request.json`：host `x230`，`/usr/bin/python3`，唯一 argv 为发布计划中的脚本路径，固定 key **`hepta-x230-b96-compiler-preflight-20261105-01`**，timeout **120s**。不附加 `--sha256`、输入文件或其他脚本参数；原源码要求 `len(sys.argv)==1`。不设置新的 CPU/memory/nice 或更改原源文件。

两项 process_start 只显式设置 LANG=C、LC_ALL=C、PATH=/usr/bin:/bin。native env 是指定覆盖，不声称外层进程完整清空环境；原探针对子命令已经使用完全显式的最小环境。

## 不确定响应的协调

- setup 或探针 process_start 的响应不确定时，保留原 request 文件，只用**同一完整参数和同一 key**对原 job 协调；有 job ID 后查询/读取原 job。不得换 key、目录、参数、脚本路径，或启动“第二次尝试”。强失败也不自动重跑。
- binary_write 响应不确定时，先使用第3项 file_info 校验原路径。若实际 bytes/SHA/mode 匹配，可保存该实际 version 作为已发布内容证明；不因缺 ACK 重写。只有明确观察到不存在时，owner 才可重新提交同一 create-only 数据请求；其他错误不等于 absent。已有不匹配文件停止，不覆盖/chmod。
- setup 在创建目录之后失败时保留部分现场，不修复、不改名重跑。此包不会预创建 `/home/qian/hepta-runtime-optimization-20261105-b96-compiler-preflight-01`；该目录仅由原探针执行时 create-only0700 建立。
- 结束时保存原 native terminal/status/read 和 `/home/qian/hepta-runtime-optimization-20261105-b96-compiler-preflight-01/report.json` 的身份；正常完成仍需读取 report.passed。退出1可能保留失败 metadata，不是允许自动改工具链/安装/基准的理由。

## 静态核对

本地仅做 JSON 解析、内联 setup 的 AST 解析、base64 round-trip 与原源/计划哈希核对，没有执行 setup 或导入/执行 preflight。工具参数与当前 ALL_TOOLS 暴露的 process_start/binary_write/file_info 声明一致；host/argv/key 习惯另对照实际 R27 component 原 start receipt。未找到本地独立 R27 binary_write 参数原件，因此 staging schema 直接按当前工具声明及既有 binary_file create-only语义核对，未伪称已读取那份历史上传请求。
