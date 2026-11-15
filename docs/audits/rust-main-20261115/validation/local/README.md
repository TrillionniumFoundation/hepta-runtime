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

后续完整 nextest 记录会单独注明源码、退出码和编译 profile。为控制此执行器
内存，使用单个 build job、关闭增量编译、debug info 和优化；这与托管 CI 的
默认 dev/test profile 不同。所有测试仍隔离运行，串行、零重试、不遇错即停。
托管 CI 保留自身的原始 profile，并分别检查 PR exact HEAD 与 prospective
merge。
