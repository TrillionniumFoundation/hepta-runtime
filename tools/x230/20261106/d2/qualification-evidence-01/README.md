# D2 资格验证、精确 CI 和完整证据

D2 是定位校验成本的诊断版本；生产采用结论仍是 R24（baab4def80be7af015b2e7a594cb302f66c4130e）。本提交没有新的性能收益声明。

## 实际完成

- 首次完整资格作业 `1a1b0cc0f51-fc05-7301`：原八阶段全部返回 0；1651 通过、0 失败、34 忽略、1685 选中、0 重试。原生输出 1111/0 B 完整、持久、确认终态。
- 首次精确 CI 作业 `1a1b0f08c41-fc05-7434`：原六阶段全部返回 0，nextest 实际 1651 PASS、0 失败、34 忽略、1685 选中、0 重试；原生输出 1545/0 B 完整。此结果是 x230 执行的仓库 CI 命令，未声明 GitHub 托管 Actions 成功。
- 首次完整资格证据归档作业 `1a1b0eac84a-fc05-73f7`：返回 0、原生输出 671/0 B 完整。归档共3614个成员、11060318 B原始payload；压缩文件2431738 B，SHA256 `2da7910b42e9babc64a3b4ddb9aa108861c3c582c707f014f76314d30a251598`。已用同一collector源在本地验证全部原件、manifest、case gzip/audit/source/harness链，**0文件提取**，没有重跑测试或原审计器。

最终222个compiler input的map为 `4bdbae5e8dea5d7534b5bde6961b44eaeaf5524553a788e171fee9fb2ecf5209`；源码树已包含真实formatter结果。19个原harness未变，D2相对已验证D1仍仅两个生产路径变化、0新增路径。资格后的diagnostic runtime为14460184 B，SHA256 `ce071bf5216a0bb5a7ce5a6871c3020cf0537d659e1a3836d7655590f8754a98`。

## 当前进行中

关闭诊断feature的原五阶段ordinary作业 `1a1b1014af6-fc05-74d2` 已首次启动并保留3个feature ELF；首个clippy阶段通过，test-build进行中。其终态、完整测试计数和postflight尚未产生，不从Q/CI推断ordinary成功。六机C1的父流程、correlation、parser及归档准备已保存，未来ACTUAL/SPEC仍未封，没有启动或宣称C1测量通过。

## 文件

本目录保留Q原preparation/report/map/test summary/完整audit、原终态/完整原生流、完整tar及sidecars、原collector启动/终态/流和本地验证记录。所有原生回执按API返回文本的原字节保存，不重编码大整数。CI原件在相邻 `exact-ci-originals-01`；ordinary首次启动进度在 `ordinary-originals-01`。各准备/封口/运输目录和独立审查保留在同一D2目录。D1原C1失败及后续独立解释的原结论没有改变。
