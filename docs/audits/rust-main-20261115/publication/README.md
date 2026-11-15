# 本地审阅提交与 GitHub 发布提交

本次终端可以读取公开仓库，但普通 Git push 没有写入凭据；发布使用已连接的
GitHub 插件。插件允许创建 Git tree 和带多个父提交的 commit，但不允许指定
author、committer 和日期。因此，**85 个本次新建的集成提交有新的发布 SHA；
原有 149 个 Rust 分支提交的 SHA 和历史保持不变**。

不是把全部修改压成一个提交。按原拓扑依次发布全部 85 个集成提交，每个提交
保留原 message、tree 和父提交顺序；只将本次新建父提交替换成其发布 SHA，
已有的 64 个边界父提交保持原 SHA。新的 HIA rewrite tips 不在这张发布图中。

| 身份 | 值 |
|---|---|
| 本地审阅链的末端 | `271039c6a983fafe5485ceca5815b7b099d5feb9` |
| 对应 GitHub 发布链的末端 | `7151927e3a1f0e0891c7a66de190b6d4fa04b1aa` |
| 两者完全相同的源码树 | `7a62f84de75ad0a0a307ea7f5f2bb2ae29f9596b` |

每次发布均检查 GitHub 返回的 tree SHA 与原本地 tree 相同。一个较大请求返回
ReadTimeout 后，读取确认目标 tree 尚不存在；随后按较小批次构造同一 tree，
最后仍要求完整 tree SHA 相等。不会用部分写入结果创建该步骤的 commit。

本目录和 HTTP 专项验证日志在上述发布链之后以一个额外审计提交加入，因此
最终 PR 的 tree 包含更多审计文件；上表精确描述已验证的 85 个提交，未把附加
审计文件说成原来就存在于该 tree 中。Rust 构建输入在这一附加提交中没有变化。

## 证据

- [commit-map.json](commit-map.json)：85 个本地 SHA、发布 SHA、相同 tree、
  有序原父提交和有序发布父提交的逐项记录。
- [local-commit-source.json](local-commit-source.json)：85 个本地原始 commit
  对象的完整字节、headers 和 message。原日志中的本地 SHA 可据此验证和还原；
  所有对应 tree/blob 也保存在发布后的历史中。
- [offline-tree-verification.json](offline-tree-verification.json)：发布前将
  实际 JSON payload 应用到各 first-parent tree，85/85 次重建均得到预期 SHA；
  原始 commit 对象的 SHA-1 也逐个复算一致。

这些记录证明源码树、拓扑和原始提交的保管。托管 CI 的成功或失败以汇总 PR
对应的 check run 为准，不能由对象发布成功推导。默认分支和旧引用的清理由
GitHub 最终状态记录；本文件不声称这些操作已在对象上传时完成。
