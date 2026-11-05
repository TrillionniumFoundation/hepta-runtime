# Compiler driver：root 准备审查 01

结论：限定的只读准入、native receipt、源码/配置/环境和协调边界中未发现确定的静态阻塞；**这仍是未选择、未执行的模板**。未运行选定路径、Rust、Cargo、native、资格或性能测试。

输入保留 `selected=false` 和全部未来绑定 `null`。源码在触及 host paths、mkdir、umask、复制或子进程之前拒绝该输入；原一次负向检查 exit2、禁止调用0，root 未重复执行。原19工具独立保留，新 driver 的实际字节及 exact diff 单独固定。

当前已采用的版本必须由真实 publication、qualification、完整源码、测试 inventory 和 ELF 相互绑定。历史 R24 不能被默认为未来最新基线；如果 R28 先采用，必须新建相应固定输入和匹配 metadata。原8阶段及测试/失败保留规则继续执行。

Native metadata 已从仅哈希 terminal 文件补全为原 start/job/key/runner、强 succeeded0、protocol1、完整持久日志、无 retry/cancel/timeout/loss，以及真实输出 footer 的语义核对。Start 的 `request/response`、terminal 的 `status/read` 是明确的保留接口；不同实际包装需要审查，不能构造成功记录。现有 R28 failed read 的131字节 stdout 文本/hex一致性只验证该原件的格式，不代表新预检已经执行。

准备器仍未实现。私有 sparse cache 的 lock/index/archive 校验、完整源码清点和新 target 构建容量必须有真实来源；driver 对未来 receipt 的 hash/字段核对不能替代这些检查。原 stage timeout 不证明所有子孙进程消失，外层 native 监督继续承担对应责任。

协调证据来自现有执行权安排，driver 不获取实时 slot，也不引入新的用户审批要求。当前 reservation23 没有移交，所有本轮新增 host calls 为0。

独立 [Cargo 范围审查](root-review-cargo-01.md) 保留。实际 `-vv`/Cargo JSON 解析尚待未来原始输出闭合；静态合理性不代表该路径测试通过。完整身份与逐项结论见 [机器可读审查](root-review-admission-01.json)。
