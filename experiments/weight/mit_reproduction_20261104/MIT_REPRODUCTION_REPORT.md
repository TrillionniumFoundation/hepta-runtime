# Weight-Space Programming：原始证据审计与可执行复现

日期：2026-11-03（America/New_York）。上游身份：`RikiyaT/lm_understand-logs`，Commit `4d09ba6d6a7e891dd8063974dfe81b3d78e3494f`。本文把上游报告、当前环境独立执行和尚未验证的结论分开记录。

## 本阶段结果

已完成三个公开网络的数值重放，其中一个完成独立环境行为评估。没有重新训练这些网络，也没有声称本次重新调用 Astra 独立发现了同样的修复。

| 实验 | 当前实际执行 | 结论与边界 |
|---|---|---|
| Exp4 Kinetix car | 从原始 PPO 权重及 prompt 中的舍入基线重建，应用 51 条公开修改，逐位比较 14 张量，并执行逆补丁 | **PASS：精确权重修复与回滚。** 6,073 个数值变化，6,149 个位级变化；未运行 Kinetix 1,024 回合 |
| Exp5 Breakout | 从零重建 20,486 参数，6 张量逐位匹配；运行固定网络、零权重与随机符号对照，各 1,000 个新 seed 回合 | **PASS：构造与新 seed 行为重放。** 未重新训练/评估上游 PPO 基线 |
| Exp6 Go budget 0 | 执行公开 336 行构造程序；14 个 `.npy` 的 Git blob SHA 全部匹配发布权重 | **PASS：零前向构造的精确重放。** 1,480,274 参数，34,190 非零；未运行 Go 对局 |
| Exp8 Qwen p50c | 从固定 HF revision 通过 HTTP Range 取得两个原始 BF16 张量，验证 base SHA，应用公开差分，验证 edited SHA，并逐位回滚 | **PASS：两张量精确编辑与回滚。** 131,072 个触及参数、130,188 个实际 BF16 变化；63.28s 含网络。MATH-500 未在本环境运行 |

`reproduced/exact_replay_results.json` 是前三个权重重放和 Qwen 差分结构审计的机器结果；`reproduced/breakout_behavior_results.json` 与 `breakout_episodes.jsonl` 是独立行为评估。所有生产模型均未参与这些实验。

Qwen 两张量的实测身份及回滚结果另外保存在 `reproduced/qwen_tensor_replay_results.json`，状态为 `PASS_EXACT_TWO_TENSOR_REPLAY_AND_ROLLBACK`。从固定版本取到的文件名是 `model.safetensors-00001-of-00001.safetensors`，由原始 index 映射得到；先尝试简称文件名得到 404，实际文件首次 Range 请求遇到 503，随后带标准 download 参数的正常请求成功。没有替换基模版本或降低 hash 校验。

## 1. 来源身份与“无工具、无训练”的真实含义

[MIT CSAIL 作者研究博客](https://rikiyat.github.io/blog/weight-space-programming/)标注 2026-11-02，作者 Rikiya Takehi、Jayden Teoh、Alex Zhang、Omar Khattab。作者给出的引用类型是 `@misc` / blog post，不能把它称为已经同行评审的会议论文。[发布日志 README](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/README.md)明确模型为 `gpt-6-astra`，Exp3/5/6/7 使用 `xhigh`，Exp4 使用 `high`，Exp8 使用 `max`。

日志的 `tool_free=true` 只说明 Codex 内建工具关闭。Exp3/6/7/8 的模型仍可在回复中提交 Python 或探测请求，由外部 harness 执行后回传结果。因此应记录“没有原生 Codex 工具”和“允许外部计算/前向工具”两项，而不能把所有实验称为没有工具。全部数据与权重来自被训练好的基础模型，只有**本次编辑/构造阶段**被限制不使用训练；基础模型训练及编辑者 LLM 训练成本并未消失。

## 2. 指定实验逐项核对

### Experiment 3：可以从中间权重识别部分结构，但不是任意模型功能全解码

[原始实验说明](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp3_language/README.md)：三个 4 层、6 头、宽 384 的字符 Transformer，分别训练于 Python、罗马字日语和英语。Astra 获得精确 forward 代码、三个候选语料类别及四个中间块的 7,084,032 个浮点数；输入/输出层被移除。允许矩阵乘法、特征值、奇异向量等权重代数，禁止在任何真实、随机或人工输入上运行网络或单层。每次最多 100 次 Python run，实际 6–11 次；每个网络两次独立对话。

六次均选中正确语料，最高类别概率约 0.48–0.62；这是一项有三个候选的诊断，不是无需接口语义的任意开放识别。模型通过前层 OV 路径与后层 QK 组合识别 induction/copying heads；独立网络前向测量用来验证，而不是提供给编辑者。必须保留阈值细节：正文使用 induction score >0.2；发布的 `scores.json` 中某字段使用 >0.3，不能直接把两个集合当矛盾或混用。证据支持所列 copying heads，不等于 24 个头的全部功能均已被因果证实。

### Experiment 4：局部电路替换修复了具体控制局部最优

[原始实验说明](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp4_fix_car/README.md)及[完整修改](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp4_fix_car/runs/oneshot_repair/reply/answer.md)：171,664 参数 actor，输入 679，ReLU 嵌入 128，再经过五个 tanh 层，输出 16 logits。PPO 用过 1,001,390,080 步但在此场景停车于坡面。Astra 获得场景、观测布局、全部舍入权重、256 回合汇总和一条失败轨迹；没有运行工具或编辑后的探测。

修复征用各层少数神经元，切断其原连接后编码“向右倒车取得助跑距离→约 x=3.8 切为全速向左→绿轮越过 x=0.95 后释放控制”的路径。上游报告 51 条修改、6,073/171,664=3.54% 数值变更，独立动作采样测试 1,024/1,024 成功。**物理场景和初态固定，随机性来自动作采样**，不是 1,024 个不同地形/动力学世界的成功。

本次读入原始 PPO 检查点，按 prompt 的 scale 重建被编辑的舍入 actor，再解析仅允许字面数值赋值的 edit 语法。14 个张量逐位匹配上游最终 actor，逆差分逐位还原。发布的舍入 actor 为 float64，原始 PPO 为 float32；直接按 float32 解析 prompt 会引入伪差异。文本整数还丢失了负零的符号，本次从独立原始 PPO 权重恢复舍入零符号，未借用目标 edited actor 补输入。6,149 位级变化比 6,073 数值变化多 76，是 `-0.0`→`+0.0`；事务回滚必须保留这些位。

### Experiment 6：从零构造网络可行，成本与比较对象要分开

[原始实验说明](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp6_go_from_scratch/README.md)：9×9 Go，243→512×6→82，1,480,274 参数，ReLU。Astra 获得完整规则和输入输出布局，所有参数初始为零，可使用 CPU NumPy；不允许训练、回归拟合、树搜索或未计费前向。一个 games pass 最多 128 局，一个 positions pass 最多 256 盘面，不能写成“50 次单样本前向”。

零预算版本使用一段 336 行程序，将棋子、气、局部连通传播、救援/吃子、眼和局面先验写成网络。上游零预算对小 PPO 两 seed 胜率 54.1%/54.9%，**对同宽深 PPO 是 42.6%/26.3%/36.3%，未获胜**。50-pass 候选才对同尺寸 PPO 达到 74.2%/70.0%/78.5%。零预算构造的编辑者墙钟约 22 分钟；50-pass 约 3h52m，其中一次 harness 暂停约 2h15m。本次全部 14 张量文件重建后 Git blob SHA 与上游一致，未额外声称 Go 胜率复现。

### Experiment 7：纯权重识别失败是必须保留的反证

[原始实验说明](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp7_sycophancy/README.md)：三对 Gemma 3 270M IT，用相同过程训练诚实与迎合版本，冻结 embedding/output。仅权重的四轮尝试未成功稳定区分，前几轮概率基本 0.5；能读到参数差异不等于知道差异的行为含义。

加入 attention tool 后，可以对每次最多 16 条自拟文本获得注意力而不看生成结果，最多 20 run。三对全部识别正确；实际 attention 调用 5/4/5 次，第三对置信度只有 55%。中层注意力对用户猜测的偏向提供行为锚点。识别、定位、用组件移植改变行为仍是不同验收层次，不能仅凭 3/3 分类宣布完整电路因果解释。该实验的 17GB 微调权重未公开，数据、训练脚本与 hashes 可供重建。

### Experiment 8：Qwen 局部方向编辑与 Gemma 的能力缺失

[Qwen 实验说明](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp8_math/README.md)、[最后报告](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp8_math/runs/p50c/work_notes/final_report.md)：固定基模 `Qwen/Qwen3.5-0.8B@2fc06364715b967f1860aea9cf38778875588b17`。只有 layers 15/19 的 `mlp.down_proj.weight` 被保留为最终补丁，两矩阵均为 1024×3584，每矩阵改 64 列。

\[
W'_\ell=W_\ell-6u_\ell\big[(u_\ell^TW_\ell)\odot m_\ell\big],\quad \ell\in\{15,19\}.
\]

`u` 是从四对 productive/repetitive 上下文的 residual outputs 16/20 提取的单位方向，`m` 选择原始模型前向定位的 64 个 writer neurons。系数是 **6**，不是正交投影的 1。触及 131,072 个值，但 BF16 舍入后实际改动 65,260+64,928=130,188。两整矩阵相对 Frobenius 变化约 10.64% 和 8.11%，参数占比小不说明干预强度小。[精确 manifest](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp8_math/runs/p50c/edit/manifest.json)记录了 base/edited SHA。

最后实践集确认是 1,152 个未用于挑选编辑的问题：579 次挽救、5 次退化，576 次挽救原本被 token 上限截断；原来已经完成的回答总体准确率未变。上游还做了剂量、单层隔离和范数匹配随机方向对照。最终隐藏基准：MATH-500 7.9→48.1，GSM8K 13.8→67.1，IFEval 21.0→62.3，MATH-500 截断 93.0→33.1%。这些结果支持“移除循环障碍使已有能力得以完成”，不证明该编辑创建了通用数学能力。

这里 50 passes 对应 158 turns、80 Python run、4 段对话和 20.3h 墙钟（其中 4.7h 连接等待）；一 pass 可 512 个生成或 1,024 段 teacher-forced 文本。最终评估可到 32,768 tokens；编辑搜索并非几秒 CPU 程序的成本。[公开 HF 复跑](https://huggingface.co/RikiyaT/Qwen3.5-0.8B-weight-space-programming)另报告同协议 2,000 个 MATH-500 生成共 43.4M tokens，在 H200 上 51 分钟得 51.0%，基线仅做了 25 题 smoke test；这仍是外部复现而非本次成绩。

[Gemma follow-up](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp8_math/gemma_followup/README.md)是重要失败：基线 MATH-500 6.8，5/10/25/50-pass 编辑为 7.0/7.6/7.7/7.0，未建立显著稳定提升。模型较少循环，失败多为普通算术/代数推理错误；放大数字特征等干预未证明能补出所缺能力。这里使用 format-agnostic 评分、8192 token 上限、每题四样本，不能与 Qwen 的 boxed-only 分数混表直接比较。

## 3. 独立 Breakout 行为重放

本次选择 [Exp5 公开零训练构造](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp5_write_from_scratch/README.md)，作为在当前 CPU 环境能完成的端到端检验。先验证从零应用 92 条修改得到的六张量与公开网络逐位一致，再使用 prompt 内的原版 MinAtar 1.0.15 环境代码；未为结果调参数。

共同协议：seed 20261103–20262102，每组 1000 回合，sticky actions=0.1，softmax 动作采样，每回合至多 10,000 步。随机对照固定 seed=871031，仅随机翻转非零权重符号，保留每张量范数、稀疏支撑、结构和参数量。零权重对照等价于均匀动作分布。

| 固定网络 | 平均回报 | 标准误 | 95% 正态区间 | 平均步数 |
|---|---:|---:|---:|---:|
| 公开手工构造网络 | 519.696 | 7.44896 | [505.096, 534.296] | 7432.854 |
| 零权重 | 0.564 | 0.02320 | [0.5185, 0.6095] | 11.748 |
| 范数匹配随机符号网络 | 0.449 | 0.01702 | [0.4156, 0.4824] | 10.522 |

本地结果与上游 517.4 兼容。这里证明公开构造权重在新随机采样中仍可工作，不能推导其在所有游戏或 HeptaTrader 上优于训练。PPO 对照只有上游成绩，其权重没有随本实验发布，本次未复跑。

运行使用 NumPy 2.3.5、CPU 四进程。将零输入连接省去后，在 1000 个独立可达状态上核验稀疏/密集网络 logits 最大差为 0。最终三组评估墙钟 39.55s；精确权重重放约 0.13s。它们只表示**固定答案重放/验证成本**，不含 MIT 最初的编辑者推理、搜索、权重下载、环境准备和编辑者基础训练。未测能源，不报告节能倍数。

## 4. 与相关方法的技术分界

| 技术 | 目标模型是否训练/求梯度 | 需要前向/数据 | HWSE 中的适当角色 |
|---|---|---|---|
| 原始权重代数、SVD、已知解析式修正 | 可不使用 | 可为零 | 提出可证伪结构假设，校验单位、边界与不变量 |
| 局部屏蔽、激活替换、因果追踪 | 可不使用 | 需要多次真实前向 | 区分失效位置，之后仍须独立权重干预 |
| 已测方向的低秩/稀疏编辑 | 可不使用 | 方向/位置选择通常需要前向 | 本任务 P1/P2 优先路线 |
| ActAdd/推理期控制 | 不修改权重，可无梯度 | 需要激活读出 | 单列“非权重修改”对照 |
| ROME、MEMIT 原版 | **使用潜在目标向量的梯度优化**，最后权重更新可闭式 | 需要数据与前向/反向 | 有价值的低成本编辑对照，不能标为严格零梯度 |
| SAE/CLT/NLA/J++ lens | 目标模型可冻结，但解释模块需要训练或 Jacobian 反向 | 需要激活/数据，有时成本高 | 作为可选解释器，完整记账，不冒充零训练 |

[ROME](https://rome.baulab.info/)将事实更新写为受约束 rank-one 修改；[MEMIT](https://memit.baulab.info/)把多事实残差分配到多个 MLP 层。但官方 [ROME compute_v](https://github.com/kmeng01/rome/blob/0874014cd9837e4365f3e6f3c71400ef11509e04/rome/compute_v.py) 和 [MEMIT compute_z](https://github.com/kmeng01/memit/blob/80426fd9316cf9a50c5ba15e0912f2c2c5bfe84b/memit/compute_z.py)都显式创建 `requires_grad=True` 的 latent delta，用 Adam 并调用 `loss.backward()`。冻结基础权重不等于整个方法零梯度。

[AlphaEdit, ICLR 2025](https://arxiv.org/abs/2410.02355v4)用保留知识的 null-space 约束来减少编辑副作用，适合借鉴“不伤害已知有效状态”约束；不能将有限保留样本下的线性不变性扩张为全部分布行为保证。[因果定位与编辑位置研究](https://research.google/pubs/does-localization-inform-editing-surprising-differences-in-causality-based-localization-vs-knowledge-editing-in-language-models/)直接说明 causal tracing 的局部定位结果未必能预测最佳编辑层。因此 HWSE 必须保留“诊断成立”和“编辑带来收益”两道独立实验。

最新主源中最贴合本项目的是 [Anthropic 2026-08-21 interference weights](https://www.transformer-circuits.pub/2026/interference_effectiveness_helpfulness/index.html)：它区分输出改变幅度（effectiveness）与消融后损失改变（helpfulness）；大权重或负权重并不自动有害。该研究先训练 transcoder、把一个 2.9M 参数的小模型展开成约 331M virtual weights；对虚拟连接的删减不能无条件转译为原模型同样廉价的参数删除。它也未获得极稀疏且无损的原网络，不能据此宣称“去干扰就会普遍增强”。

[2025 Circuit Tracing](https://transformer-circuits.pub/2025/attribution-graphs/methods.html)需要训练替代模型并做干预验证；[2026 Natural Language Autoencoders](https://www.transformer-circuits.pub/2026/nla/index.html)联合训练 verbalizer/reconstructor，存在成本、层依赖和解释幻觉问题；[2026-10 J++ lens](https://www.transformer-circuits.pub/2026/october-update/index.html)使用聚类后的 Jacobian 及学习的组合权重。它们扩展诊断工具，但都不满足本任务最严格的“无新训练、无反向”首选路线。[ActAdd](https://arxiv.org/abs/2308.10248)是由对比激活形成推理期方向的例子，应放入不改权重组。

## 5. 对三个科学问题的本阶段回答

**Q1：部分已学能力可以直接从权重结构识别并定位。** 本阶段证据覆盖特定小网络结构、部分 induction heads 与已知任务控制路径。Exp7 的纯权重失败证明，参数差异本身不足以给出可靠行为解释。模型接口语义、数据分布、激活锚点和因果干预仍不可替代；网络内部还有基变换、神经元置换等功能等价表示，不能把某个原始坐标天然当成唯一概念。

**Q2：Hepta 的解析结构可能降低搜索空间，但尚未得到相对普通网络的实验结论。** 具有明确概率语义、时间单位、边界、复位条件和共享参数的算子，有机会把候选从数亿自由度缩为可解释约束修复；这是一条结构假设。若实际故障在输入、预测封存、控制时序或缺失信息，编辑算子权重不能替代相应修复。必须用同接口、同控制器、同预算的普通核心比较“每次独立有效修复的总成本”。

**Q3：NDU 可把编辑选择转化为有成本/风险的任务动作，但优越性未证。** 合理目标是独立任务净效用增益减去编辑者、探测、验证、回滚和机会成本，尤其包含失败候选。NDU 的分数自身也可能失准，最终接受应以独立时间外样本的实际任务回报为准，不能用同一价值头自评升级自己。若没有可编辑障碍、有限探测不能形成可重复优势，应记录 HOLD，保留训练或结构扩展作为对照。

## 6. 重现实验命令及交付边界

```bash
python replay_public.py
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python run_breakout.py --episodes 1000 --workers 4
python replay_qwen_selected.py
```

前两条仅需 Python 与 NumPy、附带的固定来源文件。第三条需要访问 Hugging Face 固定 revision 的公开模型分片；它最多取 header 和两个参数张量，验证 base SHA 后才允许编辑，验证 edited SHA 后才保存，并保留精确逆补丁。生成的两个 `.safetensors` 明确只有两张量，**不能作为完整模型启动**。

原始 car 修复的可回滚记录为 `reproduced/car_exact_reversible_patch.npz` / `car_reversible_patch.json`，带来源 commit、每张量前后 hash、每个 flat index 的前后 bits。部署授权一律 false。当前全部结果仅用于隔离研究和实现验证；它们不构成 HeptaTrader 交易模型或 Hepta Neuron 核心已提升的证据。

Qwen 精确逆补丁为 `reproduced/qwen_two_tensors_reversible_patch.npz`，包含每层索引及原始/编辑 BF16 bits；上游 `edit/manifest.json` 绑定前后 SHA。本地生成的两张量 safetensors 可以由命令再次生成，因此没有重复打包进源码目录。
