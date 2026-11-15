# rmcp 3.4.1：路由构造与共享只读实例审查

结论：**factory 确实每次重建路由容器、Tool 描述和 handler 包装；Schema 本身已有线程内缓存，不能称为每次重新生成全部 Schema。** 精确发布版 API 支持借用一个不再修改的路由，同时在每次调用传入当前 server/request/context。此处是源码兼容性判断，没有编译或性能验证。

## 版本与原件

已读取 owner 的 actual-route-proof-01.json（7,479 B，SHA256 `409693f6a271fe6123b90510838079b8cc40d734ffeb672144670a5006072b54`），不重新推导测量路径。实际 Cargo.lock 为 69,305 B / `15b9fb468eb34a210238657d132cbf19e961552d1313de488e1f14936bfa4e5f`。Cargo.toml 的兼容版本声明不是最终解析版本；lock 精确选择：

| 包 | 版本 | Cargo registry checksum |
|---|---|---|
| rmcp | 3.4.1 | `5b6317cd8c13e3ec9033cf2aa5aa92cd743f0f4f8a93cddc42ea0ae6ce3b8898` |
| rmcp-macros | 3.4.1 | `d2ee366004e5f87c103be91c6c09337811517ae8d2f919ece9da7c21444b85c5` |
| schemars | 1.2.2 | `687274d293b6cdc6e73e0fee520bf2049650090d7164f87672d212a3c530cf4a` |

只对结论使用精确发布源码。官方 `rmcp-v3.4.1` 和 `rmcp-macros-v3.4.1` 两个 tag 均指向 commit **`9427a929959e665e0d12e9395f674026baf4bd48`**；该 commit 的 workspace package version 是 3.4.1，docs.rs 上 rmcp-macros 3.4.1 的 [.cargo_vcs_info.json](https://docs.rs/crate/rmcp-macros/3.4.1/source/.cargo_vcs_info.json) 也指向同一 commit、`crates/rmcp-macros` 路径。没有用 latest 或旧版代替。此轮没有读取 X230 registry 源码或下载 `.crate` 归档计算 checksum，因此不把外部发布版审查称为实际机器依赖原字节闭环。

已读取官方 GitHub ref 和 annotated-tag 对象：

| 官方 ref | annotated-tag object | dereference 后 commit |
|---|---|---|
| [rmcp-v3.4.1](https://api.github.com/repos/modelcontextprotocol/rust-sdk/git/ref/tags/rmcp-v3.4.1) | [`d63eb54bc84d228053bf536e37b691a10844bce1`](https://api.github.com/repos/modelcontextprotocol/rust-sdk/git/tags/d63eb54bc84d228053bf536e37b691a10844bce1) | `9427a929959e665e0d12e9395f674026baf4bd48` |
| [rmcp-macros-v3.4.1](https://api.github.com/repos/modelcontextprotocol/rust-sdk/git/ref/tags/rmcp-macros-v3.4.1) | [`406a5199126c520c09b5a416891a499769540291`](https://api.github.com/repos/modelcontextprotocol/rust-sdk/git/tags/406a5199126c520c09b5a416891a499769540291) | `9427a929959e665e0d12e9395f674026baf4bd48` |

该绑定将 lock 的精确包版本、官方发布 tag、宏包的发布 VCS 信息与下列固定 commit 源码对齐；lock checksum 是读取到的输入值，不是本轮重新计算的归档摘要。

## 反复构造与已存在的缓存

1. [tool_router 宏](https://github.com/modelcontextprotocol/rust-sdk/blob/9427a929959e665e0d12e9395f674026baf4bd48/crates/rmcp-macros/src/tool_router.rs) 的生成段（源码 78–90）从 `ToolRouter::new()` 起步，为每个标记方法调用属性 factory 并插入路由。没有在生成 factory 内放 LazyLock/OnceLock。结合已绑定的 71 个工具，这会在每次 factory 调用执行 71 个 Tool 属性构造及路由插入。

2. [ToolRouter/ToolRoute](https://github.com/modelcontextprotocol/rust-sdk/blob/9427a929959e665e0d12e9395f674026baf4bd48/crates/rmcp/src/handler/server/router/tool.rs) 默认新建 HashMap 和空 disabled HashSet，notifier=None（350–357）；元组转换调用 ToolRoute::new，用 Arc::new 包装 handler（184–195），随后验证名字并插入 map（436–439）。空 HashSet::new 不等于一次 heap allocation；本审查没有测 allocator 次数。ToolRouter::clone（361–368）会克隆整个 map、disabled set 和 Tool 描述，不能用每请求 clone 冒充借用缓存。

3. [tool 属性宏](https://github.com/modelcontextprotocol/rust-sdk/blob/9427a929959e665e0d12e9395f674026baf4bd48/crates/rmcp-macros/src/tool.rs) 的属性函数每次返回新 Tool；普通 Parameters 输入调用 schema_for_input。[Tool](https://github.com/modelcontextprotocol/rust-sdk/blob/9427a929959e665e0d12e9395f674026baf4bd48/crates/rmcp/src/model/tool.rs) 保留 Arc 输入/输出 Schema；有 title 时 with_title 构造 String。名字和描述使用 Cow，不能把每个字面量都算成新 String 分配。

4. [common.rs](https://github.com/modelcontextprotocol/rust-sdk/blob/9427a929959e665e0d12e9395f674026baf4bd48/crates/rmcp/src/handler/server/common.rs) 的 schema_for_type/input/output 各有 **thread_local、TypeId-keyed、RwLock<HashMap> 缓存**（源码 16–50、77–96、121–144）。线程内命中返回 Arc 或 Result 的 clone；schemars root generation，以及 input/output 的清理拷贝，只在对应缓存 miss 路径发生。空输入另有全局 LazyLock<Arc>。因此可以消除重复路由构造和热路径缓存查询，但不能声称消除“每调用完整生成 71 份 Schema”；也未证明实际请求线程的缓存命中比例。

## 借用与逐请求语义

[ToolCallContext](https://github.com/modelcontextprotocol/rust-sdk/blob/9427a929959e665e0d12e9395f674026baf4bd48/crates/rmcp/src/handler/server/tool.rs) 持有当前 `&S`、本次 RequestContext 和参数（35–68）。ToolRouter 的 call/list_all/get 都借用 `&self`（router/tool.rs 560–600）；call 将本次 context 交给已存 handler（573），方法适配器再从 context.service 取得当前 server（server/tool.rs 291–321）。factory 存的是 `Self::handler` 函数项，未捕获某个 OctofsServer 实例。

非 local 分支的 DynCallToolHandler 明确要求 Send+Sync；[3.4.1 crate features](https://github.com/modelcontextprotocol/rust-sdk/blob/9427a929959e665e0d12e9395f674026baf4bd48/crates/rmcp/Cargo.toml) 默认不启用 local，实际项目 manifest 也未请求它，lock 中 rmcp 的使用方只有 hepta-runtime。因此源码上支持共享不可变实例，仍需真正的原生编译确认最终 trait/feature/lifetime 配置。不能把该结论推广到开启 local 或需要逐 session disable/notifier 的路由。

本地已绑定 server.rs（118,630 B / `875785604d51feba6b02fdf1a6699b8d361d065a44cc4ef7bee6f931521e7e71`）未发现工具属性的 input/output schema、meta、icons 或 local 动态覆盖；src 中唯一 schema_with helper line_endpoint_schema 构造固定 JSON。没有 route enable/disable 或 peer notifier 设置调用。list_tools 取得克隆 Tool 后，另行克隆 input-schema map 再清理；保持该行为即可避免改写共享元数据。

共享对象只应包含既定路由和描述。当前 self/context、runtime visibility、owner resolution、operation policy、请求 audit、取消令牌及底层 authority 校验必须沿用原逐请求路径，不缓存它们的结果。

## tool_handler 语法与三个调用位置

[tool_handler 宏](https://github.com/modelcontextprotocol/rust-sdk/blob/9427a929959e665e0d12e9395f674026baf4bd48/crates/rmcp-macros/src/tool_handler.rs) 的 router 参数类型是 syn::Expr（8–23）；生成方法仅调用表达式的 call（44–56）/list_all（64–86）/get（88–95），并不要求取得 owned ToolRouter。返回引用的 helper 可作为表达式，例如 `#[tool_handler(router = Self::shared_tool_router())]`；这只是未编译的 API 兼容性示意。精确版本的 [docs.rs tool_handler 源码](https://docs.rs/crate/rmcp-macros/3.4.1/source/src/tool_handler.rs) 与 [tool_router 源码](https://docs.rs/crate/rmcp-macros/3.4.1/source/src/tool_router.rs) 亦已读取。

宏只补不存在的方法。因此需要同时覆盖现有手写 call_tool、手写 list_tools 的两次 factory 调用，以及 attribute 中供自动生成 get_tool 使用的表达式。只改 attribute 不会重写手写方法。get_tool 继续返回克隆 Tool；list_all 返回克隆并排序后的描述。这里没有另行证明 SDK 每个 tools/call 都会自动调用 get_tool，不能把路由 factory 次数擅自翻倍。

## 建议的最小生产改动，尚未实施

保留生成的 `tool_router()` 为原始工厂，新增一个明确绑定具体类型 `ToolRouter<OctofsServer>` 的 OnceLock 或 LazyLock，并以 `shared_tool_router()` 返回其 `&'static` 引用。初始化只执行原始 factory；若 static 放在 impl 方法内，类型必须写具体 OctofsServer，不能让 static 捕获外层 Self 泛型。

原始 tool_router 宏未指定 vis 时生成私有 factory；本项目的内部 helper 可以直接调用它，但外部 standalone example 不能未经源码调整就调用 `OctofsServer::tool_router()`。本建议无需扩大 factory 的可见性，也不以外部 example 冒充实际编译验证。

在 server.rs 只接入三个既有位置：attribute（2417）、手写 call_tool 的 router binding（2426）、手写 list_tools 的 factory 表达式（2606）。每次仍构造新的 ToolCallContext，沿用原权限和审计控制流。保留 list_all/get_tool 返回的 Tool clone，以及 list_tools 对输入 schema map 的独立克隆清理。不要加入每请求的整个 Router clone、共享可变路由状态或额外锁来缓存本次调用结果。

固定路由和属性可共享；2417 之后的 owner、runtime/tool visibility、audit admission、结果持久化与取消判定均继续逐请求执行。特别是 owner resolve/audit begin（2446–2486）、结果 admission 的拒绝分支（2491–2513）、当前 self/context dispatch（2514–2521）和结果完成/audit finish（2523–2564）不属于此候选改动。

## 必须保留的现有安全语义覆盖

以下是已定位的现有测试及应保留的行为，**本轮没有执行**。测试源码不等于候选通过证据，也不能替代真实 MCP 调用验证。

| 现有测试位置与名称 | 需要保持的行为 |
|---|---|
| src/mcp/runtime/caller_scope_tests.rs：`same_verified_credential_has_stable_private_scope_across_native_sessions`、`session_binding_refuses_different_credential_without_mutating_its_owner` | 相同已验证凭据的私有 scope 稳定；同一 session 换凭据被拒绝，既有 owner 不被污染；不同 session 的独立 owner 不被共享路由缓存合并。 |
| 同文件：`http_headers_without_trusted_extension_cannot_spoof_or_use_stdio_fallback`、`stdio_retains_random_native_session_ownership_and_no_secure_resume_claim` | 未经信任扩展验证的 HTTP headers 不能冒充 owner；stdio 的会话归属保持独立。 |
| src/mcp/server_tests.rs：`runtime_metadata_observers_do_not_admit_themselves_over_real_mcp` | 真实 MCP 下三个精确 observer 不自登记；近似名字仍按普通未知请求走审计，不缓存分类或 admission。 |
| 同文件：`served_tool_schemas_carry_no_generator_noise`、`generator_noise_is_stripped_but_parameters_named_like_it_survive` | 外部 schema 仍清理 generator 信息并保留合法同名参数；清理不能改写全局缓存中的 schema。 |
| 同文件：`results_carry_cache_hints_on_2026_07_28`、`legacy_results_carry_no_cache_hints` | 每次使用当前协商的协议版本产生 cache hint；不同连接不能沿用第一次 list 的结果。 |
| 同文件：`execution_shadow_tool_requires_runtime_mode_discovery` | 运行时工具的固定定义保持完整；该原始 factory 测试本身不能证明共享路由下的实时权限过滤。 |

已读的 caller_scope_tests 中上述检查直接测试 owner 机制；不能据此宣称已经覆盖新的共享路由 dispatch。候选若进入实现，应补齐一个有行为差异的双实例集成场景：共享同一不可变路由时，不同 server 工作根或 owner 的调用仍使用各自的当前 self/context，并在调用前继续拒绝不允许的工具。另应确认连续列举及清理不会改变以后会话拿到的描述。这是具体剩余风险，不要求建立新测试框架或重复指针身份检查。

上述已读测试原件 pins：caller_scope_tests.rs 为 5,897 B / SHA256 `77ccf054de81a644a3dc1245fffd7ce840853137205f33d93ab7c023088af950`；server_tests.rs 为 38,983 B / `003fa3365b3af0302c4a8e19f9230cea35f3366878898c1cf0920b2b6d47cddb`。

`runtime_remote_execution_recovery_and_policy_e2e` 是显式 ignored 的现有 SSH 集成测试，依赖专用身份和配置；不能说普通测试入口已执行它，本审查也没有请求启动它。审计存储的现有 fail-closed 与完成身份语义仍属于既有资格门，不能因这里仅改变元数据路径而取消。

## 尚未证明的编译与收益条件

非 local 的 DynCallToolHandler 在 server/tool.rs 191–194 明确具有 Send+Sync；local 分支（196–202）不同。结构字段与借用方法支持前述方案，但本轮没有针对实际 OctofsServer 实例化编译 `static OnceLock<ToolRouter<OctofsServer>>`，没有执行宏展开或证明最终有效 feature 集；因此最终 Send+Sync、'static 生命周期和宏生成方法仍须由候选编译检查确认。manifest 未请求 local、默认 features 不含 local，是静态输入证据，不是现场编译 feature 记录。

静态源码只确定减少重复构造的方向；首次初始化成本、TLS cache 命中分布、allocator 次数、CPU、RSS、吞吐量与尾延迟均未测。每请求 async future boxing、参数解析、权限/审计、list_all 的描述克隆/排序等工作仍存在。本轮不归因 R28 回退，不改变其固定 C1 吞吐门失败，也不声称 lifecycle ABBA 或 saturation 已执行。

## 已提供生产补丁的静态适配检查

已逐段读取 `/workspace/scratch/b96be991ab90/router-cache-candidate-01/production-only-01.patch`：2,019 B，SHA256 `d2148289912447d87f753b3a2a334e659a5048665a6aa9a906515a2f78cab79b`。在内存中比对，5 个 hunk 的旧文及行数均与上面 SHA 固定的 R24 server.rs 完全一致；没有应用补丁或改写原件。

补丁只增加 OnceLock/ToolRouter import、具体类型 static 与内部 helper，并替换 attribute、call_tool、list_tools 三个表达式。`get_or_init(Self::tool_router)` 引用原始无参数工厂，不递归调用 helper；static 明确使用 OctofsServer，helper 返回借用；私有 factory 保持原可见性并从同模块内部调用。源码 API 层面未见适配阻碍。owner、visibility、audit、结果 admission、取消与 context 构造的原控制流未出现在改动行中。

该结论是对所给补丁文本及原文位置的静态审查，不是 Rust 语法/类型/宏展开检查。尤其 OnceLock 元素的实际 Send+Sync 约束仍由真实候选编译决定；没有基于该补丁运行任何 native、Cargo、Rust 或测试。

## 审查范围

零 native 调用、零 Rust/Cargo/测试运行、零 owner 或生产源码修改；只新增本审查文件。没有运行宏展开，没有为候选建立新框架，也没有把静态分配路径折算为实测 CPU/吞吐收益或 R28 回退原因。借用缓存是可进入实现和原生资格验证的候选，不是已验证优化版本。
