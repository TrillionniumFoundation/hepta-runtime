# Candidate A：c25 固定组合审计归档

**完整替代资格：0；生产资格：0；结论：NO_GO。** 本目录整理已结束的 Candidate A 观察，不运行或重新解释 A，也不包含 Candidate B 的运行结果。通过项均为下表列明的有限门。

## 固定组合

| 对象 | 绑定 |
| --- | --- |
| Source commit | c25e4cef0610816bfd1263b69d3dd63e4114aa49 |
| Git tree | c6db025f5902570bd63520751cf84c57505eb6f4 |
| Runtime | 50,656,984 B；SHA256 9cde66234030515651177e3d8ab113b2b6f674ee76196283c71874348a0b6c90 |
| Build binding | 5,002 B；SHA256 7cee8cc6f6f141fcee5a744ae831ae0b24987e4e428bd91eb936c6ae3257503f |
| 原版 | rea-agents 6.8.0；实际安装、2,398 个包文件、tarball、Node 与 Provider 安装身份见原始收据 |

原始 binding 的构建与源码消费者结果、构建特性、工具链与完整 source snapshots 均保留。A 当时的 working tree 已被主线用于 B；本归档的源码内容只取固定 c25 Git blob，不复制当前工作目录来冒充 A。

## 已完成结果与实际边界

| 门 | A 的实际结果 | 必须保留的边界 |
| --- | --- | --- |
| Rust all-features | 2,229 passed，40 skipped | skips 不算通过；原始 nextest 日志保留 |
| Rust no-default-features | 2,201 passed，28 skipped | 独立配置的原始日志与最终显式 binary build 均保留 |
| 四个 ignored 原版语料门 | 各 1 项真实执行并 PASS | 四份输入按固定 SHA 核对；不是零测试的成功退出 |
| 116 项 JSON / Evidence 回放 | parsed 115/116；state 116/116；full object 1/116；raw frame 0/116 | 修复 14、回归 0；原始 outer failed/exit 1 是有效语义差异证据，不能改成 PASS |
| 原有 118 + 22 import 门 | 各有限比较集合通过 | 118 包含 113 response/object-order、3 tool-contract、2 canonical export；22 包含 19 response/object-order、3 canonical export。均不代表 raw-wire 相等 |
| 独立错误文本 / 顺序审计 | 38 个 JSON error：parsed 38/38，text 0/38，order 0/38；4 个 plain SDK errors：text 4/4 | 此限制同时约束原有 118/22 门的表述，不能把有限门扩展为错误文本兼容 |
| JS / TS | 7 个 Node + 原版双 oracle 案例全部一致；7 个原始 worker 回放全部通过 | 实际原版观察与投影来源、完整请求和原始 worker 双流均保留 |
| Python CI 源码回归 | 20 条命令，564 项，全部 OK | 只证明固定 c25 的源码回归；这些命令没有执行候选 Runtime 或 Cargo |
| Provider | 6 组有限门通过 | Ghidra 11、JADX 8、Chrome 14；APK 三方 20+4；MCP 6；现场生成 APK 14 个检查 / 14 个原始命令 |
| GitHub CI | 两个 c25 jobs completed/cancelled | steps/logs 未提供；不推断原因、不算 PASS。本地固定组合矩阵独立保存 |

现有 Evidence 可在新会话显式 import 完整导出 bundle；这不证明自动认证会话冷重启持久化。库存表示当时六台物理主机的有限路径观察，不能将缺失安装或未执行设备能力计为通过。

## Provider RED 与组合规则

R1 总 driver 的前五组通过后，第六组在准备阶段因实际 JDK 缺少 lib/libsunec.so 停止：0 checks / 0 commands。该 failed 收据保持原样。R2 绑定完整实际 JDK 树并明确记录缺失文件后，实际 AAPT2 version 以 exit 0 将严格预期的 50 字节版本行写入 stderr；旧 stdout-only 观察断言停止在 1 check / 2 commands，该 RED 也保留。

R3 只修正已诊断的版本输出通道观察，仍绑定相同可执行文件、严格版本字节、完整独立双流、原 14 条命令与预算。实际执行得到 12 个零退出和 2 个普通拒绝。最终 composed receipt 引用 R1 前五组和 R3 的第六组，并分别引用 R1/R2 原始 RED 与原 outer terminal，未改写失败报告、未重跑前五组。

正常 Chrome capture/cancel 是未注入运行；测试专用 constructor 的环境回执仅证明那份 instrumented exec 边界。8 个真实环境负控制及 10 个空/缺字段 executable receipt 拒绝控制保留。历史 /proc environ 的 NUL 现象和旧 RED 另置历史前缀，旧二进制不能当作 A 的通过证据。

## 文件导航

- [关键原文报告副本](summaries/)：保持原始字节，文件名扁平化仅为方便审阅。
- [审阅摘要](review-summary.json)：从原始报告提取的有限计数、绑定与 NO_GO。
- [逐文件索引](file-index.json)：原 path、归档 path、bytes、SHA256、原始身份、来源类别、Git blob 与明确 omissions。
- [完整选定原始观察归档](candidate-a-observations.tar.gz)：A 原始输入、wire、生命周期日志、driver、三轮 Provider 原始报告，四个外部语料 producer provenance，及固定 c25 相关源码。
- [归档核验](archive-verification.json)：实际解压流逐成员 bytes / SHA、集合完整性、gzip 完整读取及所有选定原文件前后不变的核对。
- [核验程序](verify_archive.py)：只流式读取 tar.gz 和索引，不解压到目录，不执行任何候选。
- [打包 original outer 回执](publication-outer-receipt.json)：打包过程结束后独立收取；它不是新的 A 功能测试。

归档中的 observations/evidence/ 是本轮 A 的已结束证据；observations/ignored-inputs-r1/ 是四份固定外部输入及其 producer provenance；observations/historical-chrome-red/ 是明确标注的历史失败；source/c25/ 是历史 Git 对象；publication-provenance/ 是本次只读归档过程与原 job 的新读回。

## 有意排除与可复核性

重复 frozen Runtime 二进制和历史 Chrome 二进制仅保留身份，不带入压缩包。原编译 target、npm 安装树、引擎安装目录、工具链与缓存不归档，它们在原始输入/环境清单中按身份绑定。B 的源码修复、focused/matrix、准备、P5 新脚本及结果均在本目录范围之外。

生成凭据 owned-real-apk-r3/workspace/keystore/test-only.p12 仅记录 bytes / SHA / 元数据并明确排除，原文件未删除。六个非本轮执行的历史测试源码存在 credential-like literal，内容也排除、保留 Git blob 和 SHA；不发布其字面值。c25 树中的旧 tests/evidence 与 tools/x230/*/evidence 不是本轮 A 观察，不带入。

所有软链只记录 lstat / link-target identity，不跟随也不写入 tar 成员；特殊文件同样不归档。included / omitted 在索引中逐项明示，未声称打包完整安装环境或整个仓库。原始观察没有脱敏改写；需要排除的整份内容以可核对的 omission 保存。

打包以单次压缩流写入，不复制大中间目录；随后从 gzip/tar 实际读取每个成员并对照索引，重新读取原文件确认 bytes / SHA 与身份未变。上述核对证明归档保真，不增加 REA 全替代、生产、全部 Android 签名策略、GDB/LLDB、ADB/Frida、IDA/Hopper 或完整成本比较资格。
