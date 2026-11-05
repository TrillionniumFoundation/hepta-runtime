# Router cache 候选准备记录

状态：**prepared / unselected / unformatted / uncompiled / untested**。本目录保存源码候选与静态来源；没有候选测试通过、性能改善、采用或全局最优结论。当前 accepted 仍为 R24。

完整说明见 [实验入口](../../../../docs/X230_ROUTER_CACHE_EXPERIMENT_20261105.md)。[router-cache.patch](router-cache.patch) 相对实际 qualified R24，只包含 `src/mcp/server.rs` 与 `src/mcp/server_tests.rs`。生产文件借用一个具体类型 OnceLock router，并替换三个既有 factory 入口；保留逐请求 self/context、owner、权限、审计、取消和返回描述/schema clone。Schema 本来已有线程内缓存，未测量 allocator 次数、CPU、RSS 或 RPS。

[manifest.json](manifest.json) 绑定完整文件身份、原测试清单、资格限制及发布范围。新增一个源码测试函数，扩展两个原测试；原有 20 个测试名和属性未移除，见 [router-tests-changes-01.json](router-tests-changes-01.json)。这不是测试执行证据，也不能把 R24 的全量 1679 selected 直接改成 1680；未来必须逐 target 实际枚举，并保留所有旧 case 名与 ignored 状态。没有新增 native/SSH fixture。

[production-only-01.patch](production-only-01.patch) 与 [production-preparation-01.json](production-preparation-01.json) 保持初始准备时原字节，后者的测试文件未改字段只描述初始时点。完整双文件 patch 是两个已完成补丁按顺序合并；原件均未改写。

静态证据原样保留：[依赖审查](dependency-review-01.md)、[请求合约审查](contract-review-01.json)、[官方源码绑定](official-source-closure-01.json)。后续 [四份原机源码核对](native-source-comparison-01/comparison-01.md) 单独记录具体闭合范围，旧审查的时间范围不变。未复制第三方完整源码或大份扫描原件。

编译 features、Send+Sync、生命周期、候选格式与完整资格仍待实际验证。native 性能执行和采用计划未冻结、未选择，没有 inventory54 或 native 窗口交接；没有设置或改动性能门，没有 reserve saturation 通过结论。发布目标仅为 `experiment/x230-router-cache-20261105`；该准备包不修改 shared/default、capacity 分支或 PR，也不包含 R26/R28 reserve 或 capacity12 源码。
