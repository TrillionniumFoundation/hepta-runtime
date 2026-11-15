# 本地 Rust 与资格工具验证记录

这些是实际执行产生的记录。每份记录只支持其对应源码、命令和环境；不能把
子分支的成功移用到最后的组合，也不能把编译中止称为测试通过。

- `clippy-corrected-gates.json`：Rust 1.95.0，完整 features 的全部 target 严格
  Clippy 在 `0730de41` 通过；无默认 features 的全部 target 严格 Clippy 在
  `7e43723c` 通过。后续供应链记录、action 固定和 Python 断言修复不改 Rust
  源码。两个相应日志保留在本目录。
- `static-gates.json`：格式和无默认 features 的全部 target 编译通过；初次
  Clippy 以 101 退出，指出 cohort 测试的多余 clone。该原始记录没有捕获 commit
  字段，故只作补充执行记录；带源码身份的修复后 Clippy 记录更强。原失败日志
  保留，`0730de41` 用 `std::slice::from_ref` 修复这一处测试写法。
- `local-qualification-integration-checks.json` 与相应日志：独立 helper 提交的
  51 个 Python 回归通过，涵盖源字节、路径、CI 契约和本地资格入口。不是一次
  在本审计 partial clone 上完成的生产二进制资格运行。
- `wsp-integration-checks.json` 与相应日志：早期 WSP 组合的字节/路由审阅结果。
  最初 nextest 编译被 SIGKILL，执行了零个 Rust 测试。该记录中的 64 条 effect
  路由是当时 WSP 组合的数字；REA 最终合并后为 66 条，不能混用。

`nextest-all-result.json` 和完整日志记录最终组合在 `4e857d68` 的全量尝试：
316.773 秒后退出 101，lib test 的 rustc 被 signal 9（SIGKILL）终止，没有
Rust 源码错误诊断，**零个测试执行**。这不是一次成功测试，且没有仅凭 SIGKILL
声称已经证明具体系统杀进程原因。为控制执行器资源，此次使用单个 build job、
关闭增量编译、debug info 和优化；这与托管 CI 的声明 dev/test profile 不同。
没有删除测试或增加重试来隐藏失败。托管 CI 保留声明的 profile，也将编译
并发设为 1，并分别检查 PR exact HEAD 与 prospective merge。

## 可独立编译的 HTTP 主程序测试

`nextest-http-bin-result.json` 与相应日志记录 `271039c6` 的主程序 harness：
14 项全部通过、无跳过，包含 8 项新增 HTTP 安全回归。命令显式选择
`--bin hepta-runtime`，所以没有编译或执行大型 lib test；此结果不替代上面的
全量 nextest 失败。编译 profile 与该全量本地尝试相同，具体覆盖及源码身份
见记录。
