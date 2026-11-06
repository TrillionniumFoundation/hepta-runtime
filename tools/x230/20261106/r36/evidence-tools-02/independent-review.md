# R36 evidence capture v2：独立源码复核

**五个core工具复核通过；R36性能拒绝结果保持不变。** 本复核仅验证扫描器修复、证据范围及本地fixtures，未执行真实export、远端命令或负载重测。fresh02 installer另行审查。

## 修复及不变量

旧扫描器在完整JSON/JSONL的字符串入队阶段积累大量重复项，虽然处理时去重，仍可先触发100k队列限制。新队列以bytes的SHA256为键保留一个待处理值；processed最浅depth另行保存。相同或更深的重复项不入队，更浅项必须更新pending或重新处理已深层访问过的内容。因此队列去重不屏蔽可继续解码的浅层路径。

七条secret规则及其flags、base64候选和hex候选模式完全未变。32 MiB单文件、64 MiB已展开数据、100,000队列/处理节点、1,000,000次JSON访问及depth 3均保持。每个真实JSON对象/值仍计入visited，重复字符串去重不减少解析访问计数。超限继续产生finding，export/verifier拒绝，而非静默跳过。

policy只新增evidence-tools-02和旧export01中唯一的export-failure.json正文。该失败原件强制绑定2,129 bytes及SHA `24ef364dc00258ad354ec5650950060ac8e91f823c6598d922b8a18452752332`；其余旧export内容只记录metadata、不递归读取。私有目录/文件、所有权、symlink/hardlink、ELF、opaque archive及固定范围规则保留。

## 独立验证

- 原12项本地fixtures独立再执行：12 passed，returncode 0，报告耗时1.700秒。包含160k重复字符串的JSON/JSONL、隐藏secret、pending浅层、实际processed深→浅重扫、原失败保留及archive篡改拒绝。
- 250个小型编码/混合深度组合：旧新scanner的finding类型完全相同。
- 真实生产界限：99,999个独特字符串通过；100,000个触发processed-node限制；100,001个触发queue限制。JSON中999,999个null通过，1,000,000个null加list root触发1,000,001次访问限制。
- 旧scanner、旧policy、旧manifest、原capture01失败字节均未变；stable_xz_archive.py保持原SHA。

本复核没有声明secret扫描穷尽所有凭据类型。真实export02是否成功及其原始证据是否完整，须在归档形成后独立核验。完整文件pins、检查范围和结果见同目录independent-review.json。
