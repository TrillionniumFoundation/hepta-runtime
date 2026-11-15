# X230 router cache：未执行的共享路由候选

**prepared / unselected / unformatted / uncompiled / untested。** 这里保存一个独立的源码实验，没有候选编译、测试、CI、CPU、RSS、吞吐或尾延迟结果，也没有采用结论。当前接受版本仍为 R24；未证明全局最优。

计划分支为 `experiment/x230-router-cache-20261105`，固定父提交 `1c23ba9ad4e7c9436eb76d1508f6f0bd8ee7ce64`、父 tree `91ef72ae803bede6a2b2d8e8eb8f25da95ad170b`，父 src tree 为 R24 的 `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`。本候选只有两个 `src` 文件变化，没有纳入 R26/R28 cancellation reserve 或 capacity12；不更新 shared/default 分支、capacity 实验分支或 PR。

## 文件与证据

| 内容 | 入口 |
|---|---|
| 实际修改源码 | [server.rs](../src/mcp/server.rs)、[server_tests.rs](../src/mcp/server_tests.rs) |
| 完整双文件补丁、身份和状态 | [router-cache.patch](../tools/x230/20261105/router-cache-experiment/router-cache.patch)、[manifest.json](../tools/x230/20261105/router-cache-experiment/manifest.json)、[README.md](../tools/x230/20261105/router-cache-experiment/README.md) |
| 初始生产补丁及准备时记录 | [production-only-01.patch](../tools/x230/20261105/router-cache-experiment/production-only-01.patch)、[production-preparation-01.json](../tools/x230/20261105/router-cache-experiment/production-preparation-01.json) |
| 完整原测试名、属性及新增测试范围 | [router-tests-changes-01.json](../tools/x230/20261105/router-cache-experiment/router-tests-changes-01.json) |
| 精确依赖、请求合约与官方源码绑定 | [dependency-review-01.md](../tools/x230/20261105/router-cache-experiment/dependency-review-01.md)、[contract-review-01.json](../tools/x230/20261105/router-cache-experiment/contract-review-01.json)、[official-source-closure-01.json](../tools/x230/20261105/router-cache-experiment/official-source-closure-01.json) |
| 后续四份依赖原件核对 | [comparison-01.md](../tools/x230/20261105/router-cache-experiment/native-source-comparison-01/comparison-01.md)、[comparison-01.json](../tools/x230/20261105/router-cache-experiment/native-source-comparison-01/comparison-01.json) |

原审查、初始补丁和准备记录保留原字节；其“尚未实施”、测试文件当时未改等文字描述各自记录时点。当前双文件状态以 manifest 为准。原审查中的绝对路径和详细扫描材料属于来源记录；这里不重复发布第三方完整源码或大份扫描原件。

## 改动及其边界

R24 的原始 factory 每次创建路由容器、71 个 Tool 描述和 handler 包装。这是源码事实，未测量对应 allocator 次数或 CPU。rmcp 已有按线程和 TypeId 缓存的 Schema；本候选不能描述为消除“每次完整生成 71 份 Schema”。首次初始化成本、请求线程缓存命中、CPU、RSS、RPS 与 p95 均未知。

新增内部 helper 返回 `&'static ToolRouter<Self>`，其 static 明确使用 `OnceLock<ToolRouter<OctofsServer>>`，初始化调用原私有 `Self::tool_router` factory。调用者借用同一个不可变 router，没有每次克隆整个 router，也没有扩大 factory 的可见性。

替换三个既有入口：`tool_handler` attribute 中供生成方法使用的 router 表达式、手写 `call_tool` 的 router binding、手写 `list_tools` 的 factory 调用。不能由此假设每次请求一定额外调用一次生成的 `get_tool`，也没有按该假设计算收益。

每次 dispatch 仍传入当前 `self`、request 和 context。当前实例 owner/workdir/view cache、模式筛选、身份解析、handler 内权限与 effect fence、审计准入和完成、取消状态仍走原路径。`readonly` annotation 是审计失败分类的输入，**不是授权开关**。Runtime config 的 OnceLock 是进程全局；测试只能在独立 child 中检查安装前后转换，不能假定两个实例各自安装不同配置。

`list_all`/`get_tool` 的 Tool clone，以及 `list_tools` 对返回 schema map 的独立 clone 和清理仍保留。协议 cache hint 按当前 context 计算；本候选不缓存整个 list response、权限结果或调用结果。

## 精确依赖与未完成的编译资格

审查绑定 lock 中的 rmcp/rmcp-macros **3.4.1**，官方发布 revision 为 `9427a929959e665e0d12e9395f674026baf4bd48`。原 dependency review 与 official closure 记录发布源码一致性及其当时未读取 native registry/归档的范围；旧记录没有改写。

后续 comparison 单独记录 root 对执行方已有材料的本地核对：四份解包缓存源码完整字节等于固定官方 revision，read02 报告中的两个归档 checksum 等于 R24 lock，四个归档成员摘要也匹配。root 没有重新下载或计算 `.crate`；四次读取是独立文件快照，并非同时原子快照。该补充只覆盖 router/tool.rs 和三个 macros 源文件，不包含 common.rs、server/tool.rs 或有效编译 features，也没有新增本候选 native 调用。

这些材料都不能替代候选实际编译。最终有效 features、宏展开、`OnceLock<ToolRouter<OctofsServer>>` 的 Send+Sync、借用生命周期及 `'static` 约束尚未通过候选编译验证。manifest 未请求 `local` 和官方默认 features 不含 `local` 是输入事实，不是现场编译 feature 记录。

## 有限的测试源码改动

扩展两个已有测试：`served_tool_schemas_carry_no_generator_noise` 从共享 router 保存按名字归一的原描述，检查重复真实 tools/list 不污染原 schema；`runtime_metadata_observers_do_not_admit_themselves_over_real_mcp` 在配置安装前预热，再检查模式切换、隐藏工具拒绝、两独立实例的 owner/audit 隔离，并保留原精确 observer 与近似未知名断言。

另加 `shared_router_keeps_workdirs_and_view_caches_session_scoped`，检查各自 root、交错 view、只改变 A 的 workdir 时 B 的路径仍独立；A 对共同绝对路径的缓存命中不能取代 B 的首个完整 view。原有 20 个源码测试名和属性保持，当前为 21 个；完整清单由 manifest 绑定到测试变更记录。这里的“真实 MCP”指测试源码使用的本地 duplex 调用路径，**不表示测试已经执行**。没有新增 native/SSH fixture。

R24 全量资格的 1645 passed、34 ignored、1679 selected 是基线结果，不是本候选结果。新增一个源码 test 函数不等于全量 inventory 必然只增加一个：同一模块可能被不同 target 收录。未来须保留所有原 case 名和 ignored 状态，并按实际 native 枚举核对各 target 与完整 inventory；现在不宣称总数为 1680，也不宣称现有 ignored SSH 集成已运行。

## 下一步尚未选择

本候选的 native 性能执行与采用计划尚未冻结或选择，没有执行窗口交接。真实 B ELF、formatter/test/release 输入一致性、完整资格、CI、依赖覆盖、磁盘和窗口都还需绑定。没有创建测量执行器，没有移用 capacity12 或 compiler 的采用门，也没有 reserve saturation 通过结论。源码方向和发布检查点不构成性能优化已验证或已经采用。
