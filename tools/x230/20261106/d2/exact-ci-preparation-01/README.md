# D2 exact native Rust CI preparation

This is an unsealed reuse of the D1 exact CI protocol. All ten actual Q pins and counts remain null in the templates. The first actual D2 qualification must finish before `seal_exact_ci.py` can bind its original report, native terminal, source map, complete isolated summary/audit, preparation inputs, and the separately sealed Q-only foundation.

The materializer uses the canonical `full-prerequisites-01/d2_prerequisites.py` and `qualification-prerequisites-01.json`. Q-only proof does not require CI success. The external R25 CI manifest is bound by its exact original path, byte length and SHA; its path is not added to generic allowed roots. The canonical public workflow and private source workflow remain distinct original inputs.

The six native stages remain cargo-version, rustc-version, nextest-version, cargo-check, nextest-list and nextest-run. The two CI workflow commands, nextest 0.9.137 identity, complete inventory, single test thread, zero retries, explicit environment, time budgets, owned-child signals/wait/reap and original stdout/stderr handling are unchanged. The runner differs only in the D2 namespace. The original auditor and canonical workflow are byte-identical.

After actual local sealing, `build_delivery.py --sealed <fresh sealed directory> --output <fresh transport directory>` creates a deterministic bounded twelve-member archive, a no-newline base64 companion, and an installer derived from the reviewed D1 installer. It does not install or launch anything. The installer validates all fixed payload bytes before an exclusive installation claim. The new canonical module directory is a fixed target; staging files and native binary-write lock siblings belong outside those target inventories.

Neither preparation nor successful exact native CI is a performance acceptance claim. No D2 CI command has been executed by these scripts during preparation.
