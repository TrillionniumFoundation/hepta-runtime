# Rust 合并候选：Python 离线验证

本轮完整执行 **35 条命令**，其中 **31 条退出码为 0，4 条非 0**。唯一发现的测试断言缺陷已单独修复，并完成对应 **33 项测试全部通过**的复跑。原始失败记录保持不变；环境受限的测试未改记为通过。

## 源码与执行范围

- 原始运行时间：2026-11-15 06:01:51–06:02:49 UTC。
- 提交：`7e43723c97c36107b271c9ba8998c7a166c75e36`。
- 源码树：`5a2f2649a90ee72daf053d065c73dee8e3bf9e4a`。
- 每条命令开始、结束时，提交、源码树及干净工作区状态均一致。
- 按当时的 `ci.yml`、`cloud-compute.yml`、`runtime-capacity-shadow.yml` 提取已检查的离线命令，最多并行两条。仅添加 `PYTHONDONTWRITEBYTECODE=1`，避免生成仓库内字节码缓存。
- CI 指定的 `/usr/bin/python3` 实际为 Python 3.13.5；云工具和容量工作流中的 `python3` 实际为 Python 3.12.14。逐条解释器身份见 [manifest.json](manifest.json)。

范围包括 REA 证据、控制面、文件描述符安全、维护恢复、X230 单元测试、云工具离线测试和容量规划。未执行真实主机操作、Colab/Kaggle 任务提交、发布或部署。Rust 测试、release 二进制集成及 HIA 专项验证由其他审计记录覆盖。

原始记录中的绝对路径是此次验证沙箱的工作区和临时文件路径，**不是用户生产主机路径**，也不表示曾连接这些主机。

## 原始结果与计数解释

以下数字按外层测试用例的**执行次数**计数，包含 CI 刻意重复的 ledger 检查和普通／优化两种容量测试；不是全仓唯一测试函数数量。

| 范围 | 命令 | 执行次数 | 通过 | 失败用例 | 错误 | 跳过 |
|---|---:|---:|---:|---:|---:|---:|
| 文件描述符安全 | 1 | 9 | 9 | 0 | 0 | 0 |
| REA ledger 与映射 | 2 | 29 | 29 | 0 | 0 | 0 |
| REA 证据发现 | 1 | 362 | 361 | 0 | 1 | 0 |
| 控制面与维护恢复 | 16 | 320 | 318 | 1 | 0 | 1 |
| X230 单元测试 | 3 | 98 | 88 | 0 | 10 | 0 |
| 并发入口与采集器 | 7 | 68 | 63 | 4 | 0 | 1 |
| 云工具离线测试 | 3 | 191 | 191 | 0 | 0 | 0 |
| 容量规划，普通及 `-O` | 2 | 58 | 58 | 0 | 0 | 0 |
| **总计** | **35** | **1135** | **1117** | **5** | **11** | **2** |

云工具分别为 Router **46/46**、Colab **69/69**、Kaggle **76/76**。REA 的 `check-mapping` 命令退出码为 0，不产生 unittest 用例数。

**原始计数器的限制：** unittest 的 `Ran N tests` 统计外层用例，而 `failures=N` 可以统计同一个用例内多个 `subTest` 失败。恢复测试的 33 个外层用例中，一个用例有六个失败子用例，正确计数为 **32 通过、1 失败**。原始记录器直接减去六次失败，得到该组 `passed: 27` 和全局 `passed: 1112`；这些原始字段未改写。[reviewed-summary.json](reviewed-summary.json) 逐条按失败用例身份去重，给出上表的 **1117**，并保留原始 `10 failures`、`11 errors`、`2 skipped` 事件数供核对。

## 失败与跳过的证据

| 分类 | 原始结果 | 证据及处置 |
|---|---|---|
| 测试断言缺陷 | 恢复测试 1 个外层用例、6 个失败子用例 | [20 号日志](20-control-plane-regression.log)：测试要求错误信息含 `dependency`，实现返回 `dependencies`。拒绝退出码、没有服务启动及 `service_action=none` 的断言均通过。仅修正测试字符串，生产逻辑未改变。 |
| 环境：Unix socket | X230 10 个错误；HTTP bridge 4 个失败 | [21 号日志](21-x230-qualification-evidence-regressions.log)、[26 号日志](26-unbounded-ingress-and-collector-regressions.log)：均在初始化时创建 `AF_UNIX` socket 被拒，`errno=1`（`EPERM`）。独立探针复现相同结果。 |
| 环境：进程观测接口 | REA 1 个错误 | [04 号日志](04-rea-qualification-evidence-regressions.log)：存活的原始子进程观测缺少 `/proc/PID/task/TID/children`。独立探针读取自己的相同接口也得到 `ENOENT`；没有声称完成该生命周期资格验证。 |
| 环境：Landlock | 1 项跳过 | [10 号日志](10-control-plane-regression.log)：内核 Landlock 不可用或禁用。独立 ABI 查询返回 `-1`、`errno=38`（`ENOSYS`）；探针没有安装任何限制。 |
| 可选依赖：pypdf | 1 项跳过 | [27 号日志](27-unbounded-ingress-and-collector-regressions.log)：PDF 提取测试的可选解析器在 `/usr/bin/python3` 中不可用。[模块可用性记录](optional-parser-observation.json) 确认 `pypdf_available: false`；未更换解释器或安装依赖来改写原始结果。 |

系统能力的独立观测见 [environment-observations.json](environment-observations.json)。这些证据说明本次运行受限的位置，并不把未完成的测试算作成功。

## 断言修复复跑

独立修复提交为 `5de427eb4c36eb290181e4a2976a4f32e7bf9af4`，源码树为 `651481eec289710ae0d1554b7152bfa37c4397f9`；主合并流程 cherry-pick 为 `0f47565fa928a436a2a3219e5167323472e74ac4`。已核对两处提交的生产文件与测试文件 SHA-256 相同。

执行原 CI 命令 `/usr/bin/python3 -B deploy/maintenance_20261017/recover_control_channel_tests.py`，**33 项通过，退出码 0**。详见 [复跑日志](recovery-assertion-fix.log) 和 [源码绑定记录](recovery-assertion-fix.json)。这是另外 33 次测试执行，没有覆盖原始 1135 次运行，也没有重跑全套 35 条命令。

## 文件索引

- `01-…` 至 `35-…`：各命令完整 stdout/stderr 日志及逐条 JSON 元数据。
- [summary.json](summary.json)、[manifest.json](manifest.json)：原始汇总、命令及源码身份；保留记录器原始计数字段。
- [reviewed-summary.json](reviewed-summary.json)：子用例计数解释、校正后的外层用例计数、失败分类与复跑引用。
- [run_ci_python.py](run_ci_python.py)：本次使用的记录器原文件，包含原始沙箱路径。
- [artifact-manifest.json](artifact-manifest.json)：本目录其他文件的字节数和 SHA-256，便于核对归档内容。

本目录仅归档本轮合并候选的结果，不包含旧 baseline 的重复日志，也不以源码映射检查代替真实主机或发布资格验证。
