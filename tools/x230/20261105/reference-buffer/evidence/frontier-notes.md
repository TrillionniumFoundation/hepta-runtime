# 本轮剩余优化边界

本轮结论限于 X230、既定六机负载和现有验证契约，不证明全局最优。R22 已大幅降低 SSH 重复校验 CPU；R23 将同一方法扩到 false/shell，因此旧 SHA 路径的成本排序不能直接代表新路径。[R22 实测](https://github.com/TrillionniumFoundation/hepta-runtime/blob/afec5354d1e0eca09f10ccabd73a01be2f14092c/docs/X230_OPTIMIZATION_20261105_R22.md)

| 具体候选 | 现有证据为什么还不够 | 语义与资源边界 |
|---|---|---|
| R23：共享 2 MiB 预算内保留 false/shell 参考 | 不能把 R22 的 SSH 收益外推到较小文件；采用取决于 R23 自己的冻结全链门。 | 完整读取、启动 SHA pin 和 owner/await fence 保留；额外驻留字节及实际 RSS 必须计入。 |
| reference 路径 16→64 KiB buffer | 新算法可能从减少 read/check 次数获益；false 的额外清零可能抵消收益。只做已冻结的一次公共组件筛选。 | 每活跃校验栈多 48 KiB，按字节取消检查变稀，竞态下错误先后可变。全局常量还影响私有 SHA 输入/fallback，公共门通过不能直接支持全局采用。 |
| 新成本结构下重选客户端并发/worker 档位 | R22 的 C16 只比 C8 小幅多吞吐，却明显增加尾延迟；尚无新排队或 worker 饱和证据支持重开扫档。 | 并发档是吞吐/延迟取舍；若修改 admission、permit、队列或拒绝规则，就改变容量、取消或资源契约，不能当作纯调参。 |

**已拒绝方向保留原结论。** R16–R18 的路径预解析、SHA buffer/复用、worker 档位及惰性分配没有建立稳定的整链收益；R20–R21 的延后 Python 导入未通过正式回退门，4 KiB/64 B request-hash buffer 也未通过小请求 CPU 门。算法发生直接变化，才有理由对 reference buffer 做这一次新筛选；不能循环重跑旧失败候选挑选样本。[R16–R18 记录](https://github.com/TrillionniumFoundation/hepta-runtime/blob/afec5354d1e0eca09f10ccabd73a01be2f14092c/docs/X230_OPTIMIZATION_20261104_R16_R18.md)、[R20–R21 记录](https://github.com/TrillionniumFoundation/hepta-runtime/blob/afec5354d1e0eca09f10ccabd73a01be2f14092c/docs/X230_OPTIMIZATION_20261105_R21.md)

省略 fresh read、只凭 mtime/旧摘要接受、跨 await 复用 worker 的旧验证结果、放宽 deadline/cancel 或容量拒绝，都改变现有权威边界。本轮不以这些变化换取性能；此前 openat2 路线的权限边界差异也不能忽略。

## 本轮停止条件

1. R23 按其原门决定采用或保留 R22，完整保留失败结果；不调整门槛或自动重试。
2. [冻结组件筛选](plan.json)只运行一次：完整 public triplet CPU 至少改善 20%，false/shell 各不得回退超过 2%。已有 rlib 无法复用、编译/记录不完整或任一门失败即停止，不启动全项目重编或参数扫。
3. 公共组件门即使通过，也只形成后续候选证据；未覆盖的私有 SHA 路径与全链行为不能推定通过。最终明确报告已采用版本、实际收益/代价、未覆盖边界和停止依据，不写“已无任何可优化空间”。
