# Hepta Runtime 全仓审计与 Rust 分支收拢

日期：2026-11-15（America/New_York）。

已完成的一次性验证资料保存在[固定历史树](https://github.com/TrillionniumFoundation/hepta-runtime/tree/93d43067bc6e0bac92a686b04cf322c564f66a81/docs/audits/rust-main-20261115/validation)；
其中的 Python 记录器、临时 Cargo harness 和原始日志已从当前树清退。所有失败、部分完成、
跳过与成功记录保留原字节；下文证据链接固定到同一提交，可恢复完整原目录进行复核。

## 已完成的结果

Rust 分支收拢已经完成：汇总 [PR #125](https://github.com/TrillionniumFoundation/hepta-runtime/pull/125)
合并为 `737acf6f901e46c57b0b4374e323e0d1132e0d49`；149 个原始 Rust 分支头全部保留在
main 的真实父链中。默认分支已切换为 **main**，149 个旧 Rust 引用与临时汇总引用共
**150 个分支已删除**，固定 **93 个旧 PR 已关闭**。操作后精确保留 main 与六个 HIA／迁移
依赖引用；HIA PR 121、122、124 保持原关系，后续外部 HIA 提交继续保留。

最终集成候选 `e425d92b6a0dedf13eb3e484e76419ee756804c0` 的 Rust 两个 PR 任务均成功：
各自 all-features 2,633 passed／44 skipped，no-default-features 2,592 passed／32 skipped。
Cloud PR 191/191 passed，三个任务的 59 个已报告步骤全部成功。实际 main 合并树与该候选
完全相同；这些计数是不同任务/模式的执行次数，不是不重复用例数量。

main push 另暴露了旧 Chrome CDP workflow 的 profile 清理失败。追加修复
[`14fc20aa`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/14fc20aabd0650784664fc9659f53936430622df)
仅修改三个 CI 文件，原 JavaScript 与五项 CDP 断言保持原字节。真实 Chrome 修复 run
[43715911837](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43715911837)
已成功，八项生命周期回归及九个步骤全部通过，产物确认 18 个本次 PID 已回收、无活子进程、
profile 已删除。Rust runtime、Cargo.lock 与其他路径的 mode/blob 保持候选原样。

[最终完成记录](completion/README.md)提供完整 CI、PR 关闭、150 项原子删除、HIA 保护、
ROG 历史工作流临时暂停及恢复、源码保全与独立回读证据。此次文档补充只写审计目录。
后续新触发且仍运行的 CI 不预先记为通过；部署和生产资格的原有 HOLD 仍保留。

## 任务与证据范围

用户要求审计整个仓库，将 Rust 开发分支合入 `main` 并清理已整合的
Rust 分支，同时保持新的 HIA 重写分支。

初始分支快照包含 **155 个远端分支**，最初 GitHub search 观察到 79 个 open
PR。后续直接 REST 完整分页发现搜索漏掉 17 个既有 Rust PR；本次汇总 PR
#125 创建后的完整清单为 97 个 open：93 个 Rust PR、三个保留的 HIA PR 和
#125。原搜索快照保留原样；完整对照、覆盖依据及 #120 保留 head 的特殊关系见
[PR 清单补充](pr-inventory-supplement.md)。初始默认分支为
`hepta-runtime-base`，提交 `ba574f2a6a1b74e85191c58d7bec011720736bb9`，
当时不存在 `main`。所有分支具有共同历史；没有把无关 Git 历史强接到项目中。

审计覆盖全部引用、完整 Git 文件树、63 个最大 Rust 分支头的差异和历史，
并深入核对 HTTP 认证、路径策略、远端执行、原始进程保管、幂等/恢复、
文件原子创建、REA、Weight-Space、CI 和证据生成路径。
原始清单、分支处理依据及失败实验原文定位保存在本目录 JSON 文件中。
这项代码和证据审计不声称穷尽所有漏洞或证明生产部署安全。

Rust 集成从 `a0dcdda1991ec536d5e2d252c006a778993fa566` 开始。
它是 Rust/Python HIA 适配器的固定基线，不含新的 `native/*.hepta` 重写树。
后续经过真实内容合并、语义冲突处理和明确的历史变体归档；未用一次全局
`ours` 选择替代源代码审阅。

## 保留的 HIA 引用

| 分支 | 初始提交 | 保留原因 |
|---|---|---|
| `codex/hia-runtime-native-20261114-bd947b55` | `ddab6e5c35444a4987d9e2bcc037f1ac895a2954` | 原生 HIA 重写，PR #121 |
| `codex/hia-request-context-20261114-7c666` | `64a0c9587f9bf6feed64e188c481402b2b16d998` | 原生请求/文件组件，PR #122 |
| `codex/hia-shell-native-20261115-194042` | `93f320a8e02b522e4bafd4a2cf346d68069ec74b` | HIA shell 组件；#123 已合入重写线 |
| `codex/hia-shell-lifecycle-20261115-194042` | `b67ba64602a18a2c8743fe33821c3f96f1f6f725` | HIA 进程生命周期，PR #124 |
| `recovery/hia-bd947-20261114` | `557220f220eb9b2e6c26a5e1c51f3546059eb236` | HIA 恢复引用 |
| `codex/hia-archive-source-retention-20261111-f9aa` | `a0dcdda1991ec536d5e2d252c006a778993fa566` | #121 的 base；原生迁移清单也固定其 commit/tree |

最后一项虽然是 Rust 适配器基线，仍属于 HIA 迁移的固定依赖。删除它可能
自动关闭或改动正在进行的 HIA PR，所以它的内容进入 `main`，引用保持不动。
目标结构是一个日常 Rust 开发分支 `main`，加上述 HIA 重写及依赖引用。

原生迁移清单仍记录 `whole_runtime_replaced=false`、
`old_stack_removal_qualified=false`、`production_activated=false`。
本次 Rust 合并不改变这些 HIA 状态，也不把 HIA 的 CI 结果当成 Rust 候选的验收。

## 分支整合原则与实际内容

149 个非保留分支的原始提交必须全部成为集成提交的祖先，之后才可清理引用。
普通内容合并和归档合并都保留父提交；未对原始分支做 squash、重写或丢弃历史。

主要实际新增/整合内容包括：

- 当前无并发数量上限基线上的后台大目录分页（#116），保留完整源校验和有限
  保管字节预算。较旧 #115 的两工作线程/硬缓存入口方案保留为历史变体。
- Colab/Kaggle provider、账户启动器和云计算路由源码及其本地契约测试。
- 可选的私有启动配置凭据、受控 macOS 配置转换工具及原始资格记录。
- Weight-Space 的 exact certificate、Bellman、trust-region、guard journal、
  cohort owner、semantic replay 和 semantic certificate。
- 45 个独立 Weight-Space Rust 研究文件保持原始 blob，不登记为根 Cargo
  workspace 或 MCP 生产组件。
- REA checkpoint/resume、instruction window、source-map embedded-content
  UTF-16 position、错误顺序和恢复协议；保留较新的完整 Evidence readback。
- 旧分支中有效但遗漏的安全改进，以及独立源校验工具、部署恢复依赖图检查。

REA 合并特意保留既有 Ghidra revision 2/3/4 分析桥的原始字节和 revision 4
GPL helper/path 检查。C3 指令桥的确切字节放在单独文件，只为新的 revision 2
instruction 路径使用；没有重绑定历史桥的哈希或重新引入固定并发闸门。

42 个历史/被替代变体位于 `archives/rust-branches/`。每个 manifest 记录原始
commit/tree、冲突来源、每个路径的 blob 和处理理由。例如 R25/R26/R30/R31/
R33/R34/R35/R36 的原始性能拒绝，以及 R27/router-cache 的未完成验收仍然成立。
归档源码可复现，不会因合并分支而自动获得性能采用资格。

## 修复的具体问题

| 编号 | 原问题 | 本次修复与回归依据 |
|---|---|---|
| SEC-01 | 不带 `--runtime-config` 的 HTTP MCP 可以绕过令牌认证，甚至监听公网地址 | 所有 HTTP 模式统一要求私有 token 文件和 loopback；保留 Origin 拒绝、常量时间令牌比较及 credential scope；新增真实 HTTP 401/403/授权请求测试 |
| SEC-02 | 先词法折叠 `link/..` 再解析符号链接，可授权一个实际访问到工作区外的路径 | 按真实文件系统语义解析原始路径；不存在的普通后缀与 dangling symlink 分开处理；覆盖现有文件、新文件及正常路径 |
| SEC-03 | Mac/Python 和 PTY 缺少原先物理 cwd 约束，省略 cwd 也可绕过配置根 | 配置执行根时要求 cwd；物理目录检查后持有 cwd 描述符；只改变子进程 cwd，保留监督器自己的私有 job 目录和 receipt 所有权 |
| SEC-04 | 本地 CREATE 的 exists-then-write 竞态可能覆盖另一调用刚创建的文件或跟随 dangling symlink | 使用 `create_new` 原子占有目标；成功后才更新 delta cache；确定性双调用测试验证恰好一个成功 |
| CI-01 | 当前主 CI 不识别 `main` | 补齐 push/PR 分支过滤，保持 exact-head 与 prospective-merge、两种 feature 模式和隔离测试 |
| CI-02 | 少数旧工作流使用可移动 action tag，且一处 checkout 保留凭据 | 15 个工作流的 40 个外部 action 调用全部固定完整提交 SHA；17 个 checkout 全部关闭凭据持久化；保留原事件、测试范围和历史源码固定值 |
| CI-03 | 旧 Chrome CDP trap 只等待直接 PID，真实 main run 在删除 profile 时失败 | 新 CI owner 保管并回收本次后代及线程组；保留原断言和失败码，八项进程回归及真实 Chrome 验收通过 |
| SUPPLY-01 | vendored ruzstd 来源清单只列最初两个补丁文件，遗漏后来三次已提交修补 | 补全六个已修改文件的 patched hash 和原始提交映射；全部 64 个上游文件记录、归档校验值和原基线不变；未修改 decoder 代码 |

SEC-03 已用实际嵌入的 Python supervisor 做临时目录实验：允许目录退出 0；
符号链接越界和缺失 cwd 均退出 127 且没有业务效果；terminal/witness 始终位于
原 job 目录。对应 Rust 回归也纳入最终组合测试。

对旧安全分支逐项核对后保留较强当前实现：私有状态根的 UID/0700 验证、Linux
`RENAME_NOREPLACE` 和 Darwin `RENAME_EXCL`、typed minimal audit、完整幂等
身份绑定、nofollow receipt、fsync 顺序及取消后原始 SSH 子进程的 guard 保管。
两个旧保护实际遗漏（HTTP 通用认证和物理 cwd）已适配到新实现，而非简单归档。

独立本地资格工具还补回了源字节、路径、Git 配置/钩子/过滤器、环境与子进程
清理约束。此次新增检查要求 index 与 HEAD 树一致，并拒绝 promisor/partial
clone 自动取回源对象。51 个辅助工具回归已通过；这次审计使用过的 partial
clone 仍按设计被资格入口拒绝，未为本次运行降低约束。

## 依赖、工作流与凭据检查

依赖修复前候选 `4767ddc0` 的 `Cargo.lock` 有 362 个 package 条目，无 `rsa` crate 或指向该 crate 的
依赖边。registry 包均带 checksum，来源是 crates.io；非 registry 包只有根包
和仓库内 ruzstd，根 manifest 的唯一 patch 也是该本地目录。此结论针对锁定
依赖图，不表示所有 RSA 算法或证书功能不存在。tunnel client 补丁的实际字节
也与来源 manifest 的 digest 一致。

15 个工作流均为 `contents: read`，未发现 `pull_request_target` /
`workflow_run` 权限桥接、job 级权限提升、显式仓库 secret 引用或下载即执行的
管道。唯一 ROG 自托管工作流保留仓库、分支及 actor 约束，没有 PR 触发。
release 仍手动触发，只构建并上传私有候选 artifact，不自动部署或对外发布。

对活跃源码、配置、脚本、工作流和 cloud-compute 测试扫描了 1,069 个 UTF-8
文件（18,811,114 字节，跳过 4 个二进制 fixture），未发现未解释的明显真实凭据。
8 处匹配均为文件引用或拒绝/隔离测试中的合成数据。没有输出凭据值；这一检查
不覆盖每个历史 blob，不能表述成整个 Git 历史绝无秘密。

最初环境没有 `cargo-audit` 和现成 advisory 数据库；后续独立取得官方
cargo-audit 0.23.0 并核对发布资产 SHA-256，使用官方 advisory-db 提交
`4ef2df8e806a65e2f1ecc14f56f51249062b23d6` 对候选 `4767ddc0` 完整锁文件扫描。
结果为 **6 条漏洞公告、2 条 unsound 提示，退出码 1，ignore 为空**。其中 MCP
HTTP 服务无界 schema 缓存涉及当前启用路径；loopback/token 只限制入口，不能
消除授权客户端造成的内存增长。两个客户端/OAuth 问题的相关 features 没有
启用，其余密码库、SSH agent-server 与底层接口风险逐项区分可达性。
原始非零报告、八份公告、工具与数据库身份以及撤回版本复核保存在
[初始依赖审计](https://github.com/TrillionniumFoundation/hepta-runtime/blob/93d43067bc6e0bac92a686b04cf322c564f66a81/docs/audits/rust-main-20261115/validation/dependency-initial-4767ddc/dependency-audit-initial-4767ddc.md)。
修复版本的实际锁文件和独立复扫应另存记录，不覆盖本次失败证据，也不能将
固定数据库匹配归零解释为整体 CVE clearance 或生产资格。

修复后的锁文件 SHA-256 为
`1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631`。
仅更新七个包记录：crypto-bigint 0.7.11、ctutils 0.4.8、rmcp/rmcp-macros
3.9.0、russh 0.65.0、rustix 1.1.6、Tokio 1.53.3；总包数仍为 362。RSA
禁用及 ring 后端保持，未增加 unsafe 或更改 SSH 信任逻辑。固定数据库复扫
退出 0，漏洞与 warnings 都为 0、ignore 为空。完整官方 sparse-index 核对
覆盖 360/360 个 registry 版本：0 yanked、0 checksum 不一致、0 覆盖缺口；
352 份原始响应按原 SHA-256 验证后压缩保留。311 个版本声明的 MSRV 均不高于
1.95，49 个未声明版本另列。详见
[修复与本地检查](https://github.com/TrillionniumFoundation/hepta-runtime/blob/93d43067bc6e0bac92a686b04cf322c564f66a81/docs/audits/rust-main-20261115/validation/dependency-repair/README.md)及
[独立依赖和注册表复核](https://github.com/TrillionniumFoundation/hepta-runtime/blob/93d43067bc6e0bac92a686b04cf322c564f66a81/docs/audits/rust-main-20261115/validation/dependency-registry-1509860c/dependency-verification-summary.md)。
两种特性模式的全部 target check、严格 Clippy 与格式检查均通过；这轮本地
检查未执行 Rust 测试；后续完整行为验证已由 e425 的托管 CI 完成，见
[最终 CI 记录](https://github.com/TrillionniumFoundation/hepta-runtime/blob/93d43067bc6e0bac92a686b04cf322c564f66a81/docs/audits/rust-main-20261115/validation/github-pr125-e425d92b/README.md)。

### SDK 分帧升级的兼容性边界

rmcp 3.9 的有界 STDIO reader 不再交付 EOF 前没有 LF 的完整 JSON 尾帧；
旧版 3.4 的 `read_until` 曾接受这种输入。这是实际兼容性收紧，不是测试误用
`decode_eof`。MCP 的 STDIO 规范以换行划分消息；本项目继续让 SDK 负责分帧，
不补造换行、不绕过有界 reader。新版默认 16 MiB 行上限同样保留，REA 的
10 MiB 原始捕获边界仍是独立且更严格的约束。

两版 SDK 的完整 codec 区域逐字节相同，BOM/CRLF 与 JSON 解析代码没有变化。
候选 `0414c548` 的两个托管 Rust 任务均执行 2,630 项：2,629 passed、1 failed，
另有 44 skipped；唯一失败是旧的无 LF 尾帧接受预期。原始日志与未运行的后续
步骤保存在 [0414 托管失败证据](https://github.com/TrillionniumFoundation/hepta-runtime/blob/93d43067bc6e0bac92a686b04cf322c564f66a81/docs/audits/rust-main-20261115/validation/github-pr125-0414c548/README.md)。

后续只修改传输测试：保留 BOM/CRLF 和 LF 正例，明确比较真实 SDK 与包装层的
EOF 拒收，验证超过 16 MiB 的行丢弃后下一帧恢复、捕获归属，以及 10–16 MiB
输入仍触发原有 REA 拒绝。生产源码、依赖锁、冻结 fixture 与其他旧测试不变。
真实模块与 SDK 的薄测试程序先复现原失败，再执行 34 项修订后的相关测试，
34 passed、0 skipped、0 retries。格式检查通过；本次全仓 Clippy 的 lib-test
元数据编译被 SIGKILL 终止，退出 101，未记为通过，也未据此断言具体资源原因。
这些局部检查不代替最终组合的全仓托管 CI。详见
[SDK 分帧兼容性验证](https://github.com/TrillionniumFoundation/hepta-runtime/blob/93d43067bc6e0bac92a686b04cf322c564f66a81/docs/audits/rust-main-20261115/validation/sdk-framing-compatibility/README.md)。

Python 直接依赖虽固定版本，但未提供完整带 hash 的传递依赖环境；包管理器
和 runner image 仍是重现性边界。

## 仍需如实保留的边界

1. **旧本地 view/editor 路径仍有检查到 I/O 的竞态。** 静态符号链接/父目录
   绕过和 CREATE 竞态已经单独修复，但普通路径检查之后的读写并非全部绑定
   描述符。不能宣称所有旧文件工具对恶意并发目录替换均安全。
2. **远端配置根的祖先目录需要可信且稳定。** `fileio.py` 的 root open 对
   最后一个组件使用 `O_NOFOLLOW`，并不逐个固定所有祖先；打开后的子路径使用
   描述符遍历。这不是完整的全路径无竞态根证明。
3. **无并发数量上限是明确策略。** 字节预算、超时、原操作身份和子进程清理
   仍存在，但总负载依赖 OS/provider 的实际资源限制。本次不把代码测试写成
   0.25 CPU / 2 GiB hostile-envelope 已通过。
4. **共享操作员 token 不是独立 ChatGPT 调用者身份。** 当前代码仍明确报告
   `authenticated_chatgpt_caller_isolation: false`。
5. **REA 完整兼容性仍未建立。** 合并后的结构性清单是 37 个 native interface；
   229 个冻结上游工具中 187 absent、23 partial、19 related，0 qualified、
   229 OPEN。重新生成当前源码映射只证明清单与源码一致，不重新认证原始参考
   资料，也不把历史结果升级成这次组合的行为证明。
6. **源码合并与生产切换是不同验收。** 原有真实 SSH 负向实验、原始会话移交、
   生产吞吐和独立 Final-use authority 的 HOLD 不能由本次分支合并消除。
7. **旧 SFTP 文件入口使用首次连接信任（TOFU）。** `src/mcp/fs/remote.rs` 对
   已知匹配公钥接受、未知公钥记录后接受，对不匹配或检查错误拒绝；这需要可信
   的首次连接环境，不是预置固定主机密钥策略，也不应称为 CA/principal 证书
   信任验证。operator runtime 的 OpenSSH 执行路径另有
   `StrictHostKeyChecking=yes`，两者不能混为一谈。

8. **macOS durable job 查找仍有随历史增长的成本。** 控制器没有 Linux content-watch
   快路时会完整校验历史记录；本次观察到的 MCP 响应超时尚未定位到确切阶段。
   原结果与静态机制分开记录，未通过重启、清空历史或新 key 重放不确定动作来掩盖。

## 验证与清理记录

上述固定历史树中的验证资料与本目录的 `verification.json` 保存实际结果；远端合并、
默认分支和引用清理结果由汇总 PR 的最终说明及 GitHub 当前引用状态记录。
只将 exit 0 的对应命令记为通过；失败、skip、环境不支持和未执行分别记录。
早期子分支的成功不代替最终组合源码的检查。

本地验证的具体结果：两种 feature 模式的全部 target 编译和严格 Clippy
通过；HTTP 主程序 harness 14/14 通过（包含 8 个新增安全回归）。35 条 Python
命令原始 31 条通过、4 条失败，执行 1,135 个外层用例；其中一处断言文案缺陷
已最小修复并 33/33 复跑通过。其余受阻位置为 AF_UNIX、`/proc` 接口，另外有
Landlock 与可选 pypdf 的两项 skip。完整 Rust nextest 在大型 lib test 编译
阶段被 SIGKILL，零项执行，未记为通过。详细计数、命令、源码和环境观察见
上述固定历史树中的各验证子目录。托管 CI 以汇总 PR 的实际 check run 为准。

首次汇总 PR #125 的托管 Rust CI（run `43686118845`，head `7f3c795b`）
在 exact-head 和 prospective-merge 两个 job 中都完成了大型测试编译；两边均为
2,629 项执行、2,626 通过、3 失败，另有 44 项跳过。三项失败均指向 REA
overflow 未识别形状回退的原文顺序契约。修复让该回退委托当前 `wire()`；
历史 native 捕获的旧投影仅在对应历史测试中明确重建，并增加直接经过生产
overflow 分派的冻结 ELF 原文回归。原始 fixture、四份 frame 哈希和逐字节
断言未改。首次失败及后续跳过步骤完整保留在
[首次 PR CI 证据](https://github.com/TrillionniumFoundation/hepta-runtime/blob/93d43067bc6e0bac92a686b04cf322c564f66a81/docs/audits/rust-main-20261115/validation/github-pr125-7f3c795b/README.md)。

同次 Cloud PR job 暴露了路由器测试在 SQLite 保存和线程启动之前设置 150 ms
租约的时序竞态；对应 push job 的 Router 46、Colab 69、Kaggle 76 项均通过。
测试修复等待真实认证 gate 和持久化 PREPARING 状态后才推进受控墙上时间，
保留真实线程、锁、SQLite 和竞争计划断言，不改变生产逻辑。修复后本地 Router
46/46 通过。REA 最终修复的格式及生产库/二进制严格 Clippy 通过；all-targets
Clippy 的 lib-test 元数据编译被 SIGKILL，零项 Rust 测试执行，详见
[修复检查证据](https://github.com/TrillionniumFoundation/hepta-runtime/blob/93d43067bc6e0bac92a686b04cf322c564f66a81/docs/audits/rust-main-20261115/validation/rea-overflow-fix/README.md)。修复后的完整托管测试
由后续 e425 的完整托管结果确认；首次失败与本地生产编译仍分别记录，不混记为通过。

由于终端无 Git 写入凭据，85 个新集成提交通过 GitHub 插件按原拓扑发布。
其文件树逐项相等；原有分支提交 ID 不变，新集成提交的 SHA 对照与完整原始
commit 字节保存在 [publication/](publication/README.md)。

`verification.json` 是其 `revision` 字段指定提交的只读复核：149 个原始 Rust
分支头均为祖先，六个保留引用单独列出，五个重写分支头均未并入；42 份归档
共验证 5,244 个原始 blob 路径，45 个独立研究文件也保持原字节。
其含义是历史与源码保管通过，不能解释为生产资格通过。

后续还保存了 [476 中间候选证据](https://github.com/TrillionniumFoundation/hepta-runtime/blob/93d43067bc6e0bac92a686b04cf322c564f66a81/docs/audits/rust-main-20261115/validation/github-pr125-4767ddc/README.md)：
Cloud 两次全部通过；Rust 预合并全特性完成 2,630 passed、44 skipped 后在下一
模式编译中被新候选替换而取消，候选任务没有完整 suite 摘要，均不作为最终放行。

[完整 96 个发布提交读回](publication/complete-96-commit-readback.json) 对应截至
`0414c548` 的 85 个集成提交、一个审计包装提交和两轮各五个修复/证据提交。
96 个文件树及有序父关系全部一致，95 个原始消息字节完全相同；早期审计包装
`7f3c795b` 的消息比本地版本仅多一个末尾 LF，该差异单独记录。原始分支提交
身份全部保持，不把这一审计消息差异称为源代码或原始历史改写。

最新的 [98 个候选发布提交读回](publication/complete-98-commit-readback.json)继续验证全部文件树和
有序父关系；97 个消息原字节相同，唯一既有包装消息末尾 LF 差异保持单独记录。
后续 Chrome CI 三文件修复的 [独立发布与源码差异](publication/cdp-lifecycle-repair/runtime-source-unchanged.json)
另行保存；实际引用清理和最终审计文档都不重写原始分支提交。


关键只读复核命令：

```sh
python3 scripts/verify_rust_consolidation.py --revision main
cargo +1.95.0 fmt --all -- --check
cargo +1.95.0 check --locked --all-targets --all-features
cargo +1.95.0 check --locked --all-targets --no-default-features
cargo +1.95.0 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.95.0 clippy --locked --all-targets --no-default-features -- -D warnings
cargo +1.95.0 nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast
python3 -B scripts/rea_compatibility_ledger.py check-mapping
```

清理阶段只删除已在 `main` 中保管的原始 Rust 分支，并以期望旧 SHA 检查每次
删除。分支若被其他工作推进，必须重新检查，不能按旧清单盲删。
新的 HIA 重写、它们的 PR 和固定基线均不进入修改/删除集合。
