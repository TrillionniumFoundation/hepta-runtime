# 路由缓存依赖：后续原机源码比对

此补充是在本地读取执行方已有原件并进行比较，没有新增 native 调用，也未重新运行源读取脚本。原依赖审查的公共源码范围保持原样。

已有 X230 作业 `1a1ace80b4a-fc05-5788` 强终态 succeeded/0，stdout/stderr 完整 8814/0 字节，持久化且无 retry/cancel/timeout。stdout 的 text、bytes_hex 和实际报告文件逐字节相等。固定 request 中脚本内容也与原 source reader 相同。

报告记录了 rmcp 3.4.1 与 rmcp-macros 3.4.1 两个归档的 SHA256 校验，并与已接受 R24 的 Cargo.lock checksum 相等；本次 root 没有下载或独立重算这两个归档。四份 source read 原件（router/tool.rs，以及 macros 的 tool.rs/tool_handler.rs/tool_router.rs）均完整、EOF、size/SHA/version 与报告 stamp 相等，四份内容逐字节等于官方 revision `9427a929959e665e0d12e9395f674026baf4bd48` 的相应源码。归档成员摘要也与这四个源码摘要相等。

这四次读取是每文件稳定快照，不是同时原子快照。当前补充不包含 common.rs、server/tool.rs、有效编译 feature 或候选宏展开；不证明候选编译、测试、性能或采用。完整路径、身份及限制见 [comparison-01.json](comparison-01.json)。
