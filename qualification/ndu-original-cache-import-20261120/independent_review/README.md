# 原 mastery 缓存恢复路径：独立源码审查

**结论：在下述固定身份与执行条件下，源码审查通过，未发现阻断问题。此结论不代表已经激活、实际回收或释放原任务资源。**

审查者：`/root/finite_update_theory`。审查日期：2026-11-20。独立审核相对于实现者的 77 项测试；读取这些测试以检查覆盖面，但未将作者测试结果计为独立执行证据。本次未调用远端、未修改 candidate 源码、未修改生产状态或锁。

## 允许应用的原任务

| 绑定项 | 固定值 |
| --- | --- |
| router request | `ndu-repair-mastery-20261120-aa42a9-v1` |
| provider request | `hc-301097a07c1fb980f74152da554a52be6339c371` |
| account | `qiqian` |
| kernel / version | `146145883` / `1` |
| 原提交状态 / provider 终态 | `ACCEPTED` / `COMPLETE` |
| 原 input digest | `46d55a369a08fa3f2b61afa90b1e9c16de97778ed4fb7f00ddae8943e4de35bc` |
| 原 notebook ref | `alexqipku/hepta-hc-301097a07c1fb98-74fa89c23f4383d76acd1c0d` |

历史 sunfo 未取得原 ACK/kernel/version 的未知任务不满足入口条件。现有本地字节不构成该任务的提交身份，也不授权重提或清锁。

## 审查依据和结果

`CACHE_CORE_STATIC_REVIEW.json` 保存固定源码 SHA、原函数 AST 比对及逐项结论。核心比对确认 68 个原函数 AST 不变；`qualification/hepta_compute_base.py` 与 deployed 原 router 字节一致。只读审查涵盖核心 adapter diff、实际 CLI 使用的 CreateOnly 子类、账户 launcher、原 router 收集路径，以及 `test_recovered_cache.py` 和 `test_original_router_collection.py`。

1. **身份与 provider 权威。** 首次导入需要原 `ACCEPTED` 和正整数 kernel/version，继续使用原账户检查、状态检查和源文件身份检查。进入完整输出收集前，需要原任务新鲜 `COMPLETE` 观测；缓存不能建立或替换原提交身份。
2. **当前 manifest。** 导入时 manifest 始终从固定版本 provider catalog 重新取得。实际字节必须匹配调用方预先固定的 SHA，manifest 中 request 必须等于原 provider request，声明路径必须完整覆盖该版本输出目录除 manifest 自身外的全部文件。
3. **CreateOnly 完整路径。** 实际 CLI 使用的子类保留完整 output path 的权威 catalog；provider 展示的 basename/size 冲突仅作提示，不能取代文件身份。子类通过新的 catalog hook 复用基础 artifacts 验证路径。
4. **缓存真实性。** 缓存文件通过 no-follow 文件描述符逐段打开，要求本人所有、普通单硬链接文件；校验完整字节长度、SHA 和复制期间元数据稳定性。私有新 staging 完成后再次校验。清单文件的 HTTP 来源和 payload 的本地缓存来源分别记录，缓存 payload 不伪造 HTTP Content-Length。
5. **receipt 复用与正常结算。** receipt 绑定原 input digest、kernel/version、manifest 身份和来源策略，不能回退伪装旧 HTTP receipt。已发布缓存的本地复用本身不再次请求 provider，但原 router `collect` 在正常请求/账户锁下先做新鲜观测，核验 execution wrapper、全部复制内容和必需输出，再调用原 `finish_collection`。审查未发现旁路手改 DB 或锁。
6. **失败和成本。** 原事件记录机制不变；失败先形成事件，再移除临时下载 staging，保留原事件和已发生尝试。实际执行的时间、远端调用、下载和恢复费用仍须进入外层成本记录，不能由“无新训练样本”推断为零成本。

`RECOVERY_PREPARATION_STATIC_REVIEW.json` 分别检查两份 preparation 脚本的固定原输入、实际 SHA 常量、launcher 变更与准备/激活边界。

- `prepare_external_cache.py` 仅从原已保留 manifest/archive/summary 的固定字节重建外部私有缓存。2336 份 payload 总计 6,635,423 字节；包含 manifest 为 7,002,550 字节，保持在原 8,388,608 字节限额内。重建按内容长度和 SHA 精确对应，不根据归档成员名猜测 provider 输出身份；前后检查原 request 和输入字节未变。
- `stage_release.py` 验证五个旧版与新版模块的完整 hash，验证原 launcher/live entry，create-only 建立新 release 和 launcher。原 launcher 只改变一处 batch release 字符串，函数和类 AST 不变。脚本执行新 CLI 的 `--help`，检查缓存参数可用，最后仍要求当前 live entry 未变，只输出 `PREPARED_NOT_ACTIVATED`。

## 已固定的执行条件与未执行步骤

两份 preparation 使用 Python `assert` 作为检查。**实际运行必须显式使用固定 Python 的 `-I -B`，不使用 `-O`**；`-I` 排除 `PYTHONOPTIMIZE` 等环境配置关闭断言。无需改动已冻结源码。

激活仍需外层执行：读取当前 live entry 并验证原 SHA，使用精确 `expected_version` 的 CAS 写入 proposed entry，再读取并核对 proposed SHA。之后依次使用原账户 CLI 导入缓存和原 router `collect`，保持原 8 MiB 上限，并检查原任务的实际状态与证据。上述远端步骤均不属于本次已经完成的工作。

回滚只恢复入口字节，并以当前 proposed SHA/版本作为前提；不删除新 release、cache provenance receipt 或旧失败记录。旧 adapter 不支持新 receipt 的来源策略，不能将已经导入的本地 payload 重新解释成旧 HTTP 下载。此限制已在 preparation 中明示；入口回滚并不撤销已经完成的导入。

## 入口切换与回滚的追加独立审查

收到实际控制器 `entry_switch.js` 后，另外完成固定源码审查和独立本地模型验证。`ENTRY_SWITCH_INDEPENDENT_REVIEW.json` 保存全部 24 个场景及各自工具调用轨迹；`review_entry_switch.mjs` 是独立编写的模拟器与检查程序，不复用作者测试代码。测试调用固定候选函数，工具仅为内存中的三个 fake 函数，没有远端工具接入口。

24 个场景全部通过，覆盖：scope/commit/mode 不合法时不调用工具；旧版或新版依赖、原 router、原入口身份、权限、所有者和链接数异常时不写入；保留文件版本、完整读和摘要异常时不写入；原入口版本竞争时按原 `expected_version` 拒绝且不重试；写入响应不明、写后 hash 或元数据校验失败时进入明确的人工核对状态；正常激活和精确回滚；新版 release 不再可读时仍可使用完好的旧版依赖回滚；第三方已换入口时拒绝覆盖。全部模拟写只指向固定入口，原 request/DB/锁/缓存 provenance receipt 哨兵保持原字节。

源码检查还确认：新 release 的五份本地模块覆盖全部内部 imports；动态 `kagglesdk` 加载继续位于字节未变的 transport，并使用既有 venv；未新增 SDK 依赖。原入口 295 字节、新入口 300 字节和新 launcher hash 均从实际保留原字节独立推导一致。控制器加载不执行操作；只接受固定 mastery scope，调用者仍须先完成真实源码冻结，`frozen_commit` 字段本身不是对仓库存在性的远端验证。

控制器的错误返回区分 `NO_MUTATION` 与 `RECONCILE_EXACT_ENTRY_DO_NOT_RETRY`。后一状态只说明尝试过写入，需要读取同一入口进行核对，不能被解释为写入一定发生或一定未发生。成功结果也仅为 `ENTRY_ACTIVATED_ONLY` 或 `ORIGINAL_ENTRY_RESTORED_ONLY`，不伪称原云任务已经收集。

本地模型的测量正文 CPU 为 0.095040 秒、正文 wall 为 0.071002481 秒；执行工具记录的进程等待时间为 0.106177059 秒。测试范围是控制器对所模拟官方 API 契约的行为，未验证远端可用性，也不能替代真实 CAS/收集回执。原核心审查文件中的 `PENDING_SEPARATE_REVIEW` 是当时阶段快照；本节和新增独立报告完成了后续源码审核。

## 固定候选源码

| 文件 | SHA-256 |
| --- | --- |
| `kaggle_jobs.py` | `7a4f8ea009f3761a63e7fdffc80ecc8759df68aeb6bb11e692f659d483c4ca1b` |
| `kaggle_create_only.py` | `9bc161048319d14e0cf855f6d4aa937478486842237b1ca6675b5b68e60e0648` |
| `kaggle_transport.py` | `99e44c8054eab22534399de3eef9088fcbb98406f64726ab99241d6b5054566c` |
| `hepta_kaggle.py` | `5cbc8455d4482f3d6223cb51f981c302780779f4a1f51325076dea4583a2f864` |
| `tool_contract.py` | `fd5e91d791831d6eca57594ea925e78ff3d9426d08c69c3b326f2a24d6bb89da` |
| `prepare_external_cache.py` | `c7981ba8b4dce9a474e97b335fbd148fda236588a881c1a197c461e7e5f9f413` |
| `stage_release.py` | `65c470c194e2150a82060dc6d775c589d4eba8c659e666666b4f966334c3fc9e` |
| `entry_switch.js` | `e86acaf8ee5cebbdb06ddc7bb8ab420575ec0d69651859a8675de5c7754a7b76` |
| `original_account_entry.bin` | `83cb827b69028c6312ea1560c92d9cbb6c5fd6eb0dbb5597623f98b12a76b5de` |
| `proposed_account_entry.bin` | `c60bc1bacac20aec5dce2e3acc18bcc30ee03cd96a686d489bafe6dc0ce16653` |

本审查只适用于这些固定字节和原任务绑定。实际回收应以随后产生的新鲜执行记录为证据；“源码无阻断发现”与“已经回收成功”是不同的结论。
