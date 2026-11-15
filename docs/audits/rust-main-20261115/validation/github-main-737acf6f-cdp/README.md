# main 合并后的 Chrome CDP workflow 失败分析

**实际失败在退出清理，不在 CDP 导航或 DOM 断言。** Run [43709528201](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43709528201)、job `132797850509` 的 step 4 `Real browser and loopback-only test HTTP server` 失败，完整日志给出：

```text
2026-11-15T11:34:32.2909493Z rm: cannot remove '/home/runner/work/_temp/rea-cdp-chrome-profile/Default': Directory not empty
2026-11-15T11:34:32.2934830Z ##[error]Process completed with exit code 1.
```

错误来自 workflow 第 71 行的 `rm -rf "$profile"`，位于 `EXIT` trap。该 job 结果保留为 failure。原始日志、全部 job steps、run metadata 与 GitHub 产物均保留；不把已经取得 CDP 观测改写为整体 job 成功。

## 已确认的实际观测

下载的原始 artifact `14160096176` 为 3785 bytes，SHA-256 `bb11bfb0d4c79567d71a82d278be7c29502588a61dff4f6ec0d6d233bb309b12`，与 GitHub API digest 相符，ZIP CRC 也通过。里面记录 Node `v24.22.1`、Chrome `157.0.8103.50`，以及 `real-cdp-observation.json`：

- provider 为 `real-google-chrome-cdp`；
- 实际页面 title 为 `REA CDP reference`、text 为 `REA-CDP-REAL`，URL 指向本次 loopback fixture；
- `navigationFrameIdPresent=true`；
- `productionAdapterQualified=false`。

保存的观测满足原 workflow 五项 Python 断言；artifact `cdp-test.mjs` 与失败 commit 的内联 Node 源码逐字节相同。日志没有实际 CDP timeout、Page.navigate 或 DOM 断言异常。浏览器日志里的 D-Bus 警告和 favicon404 仍完整保留，但不是 job 报出的退出错误。

## 源码与原因边界

失败源 `737acf6f901e46c57b0b4374e323e0d1132e0d49` 和 candidate `e425d92b6a0dedf13eb3e484e76419ee756804c0` 的 `.github/workflows/rea-browser-real.yml` 逐字节相同，SHA-256 为 `17c8511deb9909430a2ce2e6ea199c8e317fe41c80dc26b845cfd35ae7d74884`。`source-binding.json` 记录精确行号和历史。

原 cleanup 仅 signal 两个直接 PID，`wait` 这两个 shell child，然后删除 profile；没有证据确认 Chrome 所有子进程/写入者已退出。它从原始 workflow commit `14a5b75d` 起未变，后续 `3032267b` 对该文件只增加 main push 分支。因此应归为**启用 main 后暴露的既有 CI browser teardown 生命周期缺口**。Chrome 子进程或其他存活 writer 在删除时再建目录项，是与 `Directory not empty` 一致的竞争机制；没有进程树快照，不能声称已确认具体 writer 和时序。

此 workflow 只执行 CI 内联 Node/Python/Chrome，不构建或运行 Rust runtime；没有依据将此失败归为 rmcp/REA 业务回归或缺 Chrome/Node。candidate e425 的 Rust/Cloud PR 检查通过，但该 Chrome workflow 只有 push/manual 触发，并未包含在那两项 PR 检查中，不能宣称它在 e425 上已通过。

Run 创建于 `11:33:49Z`，紧随 PR125 的 `11:33:46Z` main merge；失败于 `11:34:32Z`。分支删除开始于 `12:23:12.843740Z`，所以这次失败与删除无因果关系。

## 最小修复建议，尚未实施

只调整 CI 的浏览器启动/清理所有权：把本次 Chrome 及后代绑定到可确认的 owner/process group，有界关闭并确认所属 writer 退出/回收后，再删除 profile；保持原 probe 返回码、五项语义断言和严格 cleanup 失败。不要给 `rm` 加 `|| true`、删除清理要求或使用全局 `pkill`。单纯重试目录删除也不证明浏览器进程树已经结束。独立进程组也不能自动证明所有后代仍在组内，必须核实实际 owned descendants 已退出。

建议以一个可控后代持续写 profile 的局部回归验证清理顺序，再由实际 Chrome workflow 验证。这里没有执行拟议修复、复现或重跑，因此不提供虚假的修复通过结论。

此次只读取 GitHub metadata、完整 job 日志及小型 artifact，解码有界文本/JSON，未执行产物内容；没有 host calls、修改仓库/工作流/配置、重跑/取消或触碰封存 e425 CI。下载临时签名 URL 未写入证据。`manifest.json` 校验本目录除自身外全部文件。

独立 security_audit 只读复核同意上述失败点、五项观测、源码身份和修复范围；具体记录见 `independent-static-review.json`，没有另行执行测试或 host 操作。
