# R23 后最后一次 reference buffer 组件筛选

**已准备，未编译、未运行、未采用。** 本轮只比较 16 KiB 与 64 KiB。先前 SHA 路径的 buffer 结果不能当作 reference 路径的测量证据；也不能仅凭 read 次数减少宣称会改善 RPC。

## 源码与低成本边界

`prepared/component.rs` 已从实际 `r23-tested-source/` 生成，绑定 profile SHA `a62169343c2a08c38d69925f33fdc7551cf4be7b4b7f50cf89683f652a8f853a` 和完整 220 项源码映射。`prepared/arm-diff.txt` 只有 VERIFY_BUFFER_BYTES 的 16→64 KiB 一行变化。两个 module 共用一个独立二进制；不修改冻结 R23 源码。

PinnedFile、完整文件读取、stamps、固定 shell resolver 和 R23 三公共文件 load/budget 顺序按原文提取。计时使用真实 CancellationToken 与 Tokio Instant，check_current 方法体也按原文提取；只提供其需要的薄字段结构，没有新 worker、admission、permit 或 owner 生命周期框架。shell 场景保留 verify_resolution，triplet 保留每个公共文件外层 current 检查。

启动仅对 /usr/bin/ssh、/usr/bin/false 和固定 /bin/sh 解析目标取公开文件指纹，再令两个 arm 执行原始 SHA pin load。没有读取生产私有 profile、SSH config 或 known-hosts 来取得 pin。这是组件输入绑定，不是私有生产配置资格。

## 冻结的单次筛选

四个场景：SSH、false、shell、三者按生产顺序组成的 public triplet。每个场景三块 ABBA，每 cell 256 次，每 arm/scenario 先预热 8 次，共 48 个计时 cell。原始 JSONL 保留每个 cell 的 wall/thread CPU/process CPU 起止值；不删样本、不自动重试、不扩大参数范围。

主门为完整 public triplet 的平均 thread CPU：64/16 ≤0.80；false 与 shell 的单文件 CPU 比值各 ≤1.02。每块方向和按一文件一次频率计算的单文件 CPU 和另列诊断；这些有限样本不是置信区间。预检只检查公开文件的完整 mismatch 读取、最终内容错误、取消/到期拒绝与晚取消优先，不把它描述为完整竞态或 syscall 错误测试。

现有 R22 的 SSH 机制 CPU 约 0.1818 ms，12 次约 2.18 ms/request；相对 C8 的 28.333 ms controller CPU/call，要仅靠这一项降低 3% 总 CPU，组件约需降低 39%。这是量级计算，不是 64 KiB 的收益预言。三文件 reference 合计 1,003,608 B，结果以实际 public triplet 测量为准。

正常满块读取下，三文件非空 read 块数 62→16（含 EOF 65→19），PinnedFile 内部 current 检查合计 207→69。64 KiB 因而改变每字节的取消检查频率和竞态下可观察错误先后，不能声称检查次数或取消时点完全相同；每个活跃 verify_checked 栈数组还增加 48 KiB。false 只少一次 read，额外清零成本可能抵消收益。

**全局 VERIFY_BUFFER_BYTES 还影响私有 profile/config/known-hosts 和 SHA fallback。** 本筛选有意不读取这些私有输入，因此即使 public 门通过，也不构成全 profile 不回退或采用全局常量的证据。任何后续范围选择另行审查；失败则停止这个方向。

## 准备、绑定与实际运行

本次只执行了 prepare（纯源码读取/文件生成）：

    python3 -B buffer_screen.py prepare --source R23/source --output prepared

待 R23 完整资格及正式 campaign 结束、root 单独安排后，在 X230 用原成功 qualification 绑定已有依赖：

    python3 -B buffer_screen.py bind-build --source R23/source --prepared prepared --qualification R23/qualification-01 --output attempt-01

该命令只写 `attempt-01/build-plan.json`，不会调用编译器或负载。它核对 220 项实际 source_tested/source_after、test-build 原 stdout SHA，并从原 `cargo-no-run.jsonl` 唯一选择六个已有 opt-level=1 rlib，记录其实际 SHA/大小，然后输出一个 rustc argv。缺失、歧义或链接失败即停止，不调用 Cargo，不安装依赖，不重编全项目。

由现有 owned-process runner 执行这个 rustc argv（90 秒预算），保留 rustc -vV、stdout/stderr 和编译退出/回收记录。固定静置 30 秒后，运行生成的 component 一次（60 秒预算），保留完整 run.stdout/run.stderr、退出/回收回执和前后机器观察。RUSTUP_AUTO_INSTALL=0、MALLOC_ARENA_MAX=1；记录真正编译器版本，须为 1.95.0。现有 runner 负责 timeout 后只回收其自有进程组；本工具没有另造生命周期框架。

用下面命令复算，不执行负载：

    python3 -B buffer_screen.py summarize --stdout attempt-01/run.stdout --output attempt-01/summary.json

summary 的 component_records_valid 只说明这份 JSONL 通过固定矩阵/算术检查，必须同时保留实际编译与运行成功回执、二进制及依赖前后身份；它永远写 candidate_adopted=false。当前 Rust harness 尚未编译，不能宣称编译或运行通过。若现有 rlib 无法直接复用，则按冻结停止规则结束，不为它引入另一轮项目构建。
