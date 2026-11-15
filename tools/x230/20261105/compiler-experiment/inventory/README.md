# 只读 source / public registry inventory 模板

**prepared-only；尚未选择参数，未在 native 执行。** [input.template.json](input.template.json) 为 `selected=false`，accepted、metadata 和所有路径保持 null。[inventory.py](inventory.py) 在该状态下只读输入文件并拒绝，不访问选定源码、缓存或创建证据目录。原 preflight、qualification driver、计划及发布文件未改。

## 最小接口

调用方在实际 metadata 成功且确认届时 accepted 后，另存一份带实际 size/SHA 的新输入：accepted publication / qualification / source-map、metadata report、原 19 harness map，以及 source、旧 Cargo home、容量观察目录和**尚不存在**的证据输出目录。原模板不原地填值；native 协调与 terminal 闭合仍由调用方和现有 driver 处理。

```text
python3 -B inventory.py --input NEW_FROZEN_INPUT.json --input-sha256 ACTUAL_SHA256
```

需现有 Python ≥3.11（标准库 tomllib）；不安装或选择替代解释器。没有 Cargo/Rust、子进程、网络、复制、解包或清理操作。

## 读取与输出范围

- 完整遍历指定 source，记录文件原字节 SHA/size/stat，独立核对 accepted 编译 map 和原 19 harness。凭据、Cargo 配置、Git 管理数据、旧 target 等命名位置只记元数据/阻塞，不静默裁剪为“完整”。仅内容覆盖完整且两种绑定匹配时才写 `full-source-map.json`。
- 仅在指定 Cargo home 的 `registry/index` 下做有界 namespace 发现。公共名称候选的 `config.json` 必须符合固定 crates.io 匿名端点白名单；报告只保留结构和身份，不输出正文、未知 URL 或凭据。
- 根据实际 Cargo.lock 枚举条目，读取对应 `.cache` 文件身份及 `.crate` 原始归档 SHA，并分别报告缺失、不支持和 archive↔lock checksum 结果。不会读取 `registry/src` 或归档成员。内部 sparse 格式及对应版本 `cksum` **不解析、保持 unknown**。
- 写新 `report.json` 和纯相对路径→SHA 的 `registry-observed-map.json`。后者是观察集合，可能包含 checksum 不符项，**不是复制允许清单，也不是已经准备好的私有 registry manifest**。

证据目录拒绝复用，创建后保持其 fd；文件以 `dir_fd + O_EXCL + O_NOFOLLOW`、0600 写入并核对目录身份。成功 footer 同时给出实际 report 的 path/bytes/SHA；失败尽可能在原目录 fd 保存独立 `failure.json`，不会转向被替换的路径。部分绑定输入也先经纯内存检查再接触所选路径。

`inventory_complete=true` / exit 0 仅表示有界清点完成；缺包、未知项仍可能存在。它不是 preparation、qualification、离线解析或构建通过；Cargo.lock 全集不是实际 target/features/host-build 依赖闭包。

## 容量与边界

记录实际逻辑/分配字节、statvfs 可用字节/inode；不计算可回收空间，不填归档展开量或清洁构建峰值。16 MiB 是本工具**证据写入总量上限**，并单独检查该证据空间，绝不是构建预算。读取另限 120 秒、20,000 个 source 项、每文件 64 MiB、累计 2 GiB；超限或变化保留失败状态，不自动重试。全程有限身份检查不构成持续锁；后续 preparer 必须重新核对原件。

现成 preflight 只覆盖已知编译 map，现有 driver 只核对已准备输入，R28 旧 inventory 只清点固定 compiled targets；均未覆盖本范围。本稿沿用已有稳定目录/文件身份读取方式，不添加新协调或认证层。静态审查与最多一次 unbound 拒绝验证记录在 [manifest.json](manifest.json)；没有模拟成功或性能结果。
