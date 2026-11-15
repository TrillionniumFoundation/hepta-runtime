# R36 validation-scratch cold02: original exact CI preparation

This is an unsealed, unexecuted preparation for PR108. The compiler input anchor is accepted R24 `baab4def80be7af015b2e7a594cb302f66c4130e`; the candidate changes only the observation-profile implementation and its reference tests. It is separate from the earlier audit-cache candidate that also used the label R36.

Runtime root: `/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02`  
Cargo home: `/home/qian/.cargo`  
CI output: `ROOT/rust-ci-01`; plan: `ROOT/rust-ci-plan-01.json`.

## What changed

The launcher and runner are exact R35 source with the experiment namespace replaced. The materializer has that namespace replacement and one effective-environment Cargo home replacement. The sealer has the namespace replacement, the identities of the three derived templates, and one description clarifying cold preparation. The nextest auditor and canonical workflow are original bytes. The complete diff, exact identities, local static checks, and independent review accompany this package.

All ten materializer qualification values and the launcher SPEC are `None`. The example receipt input contains ten unbound slots. No qualification counts, successful job ID, formatted source map, or future CI outcome is filled from a prediction. The prior D2 feature test count is not a count for this candidate.

## Bind only actual completed qualification evidence

After the original qualification has completed, preserve the original preparation report, qualification report, source map, isolated summary and audit, and native terminal status. Use the exact installed preparation launcher, qualification input, candidate patch, and final reviewed parent source as the other four inputs. The ten remote paths and the required `local_path/path/bytes/sha256` shape are in `actual-pins.example.json`.

The parent dependency is `ROOT/tools-01/r36_campaign.py`. Its final source must expose `bind_r36_candidate_preparation(inputs, bind)` and the original `checked` reader. Its static preparation seal binds this cold02 preparation; it does not depend on a CI outcome. This package does not supply or pin an unfinished parent draft.

The data-only local command is:

```text
python3 -B /absolute/preparation/seal_package.py --pins /absolute/actual-pins.json --out /absolute/new-sealed-output
```

The output directory must be absent. The sealer reads immutable copies, checks original successful qualification/terminal/report/count identities, parses the parent AST, and writes new files. It does not import or invoke the parent binder, run a compiler, run tests, run an auditor, contact a host, or launch a subprocess. It writes six tools under `tools/`, one qualification-bindings JSON, the exact supplied pins JSON, and a seal manifest. Unknown or unsuccessful qualification evidence is rejected before output creation.

The runtime materializer later loads the exact parent as a non-main module and calls its qualification-only binder before materializing the plan. This is a runtime read-only prerequisite check, separate from the data-only local seal. Keep the original qualifier and all 19 harness files unchanged.

## Original commands and ownership

The original commands remain:

```text
cargo check --locked --all-targets --all-features
cargo nextest list --locked --all-targets --all-features --message-format json
cargo nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast
```

Exact CI obtains offline behavior from its original `CARGO_NET_OFFLINE=true` environment. No extra `--offline` CLI option was added to these workflow commands. The original qualifier's own offline flags remain unchanged.

The six stages are cargo-version, rustc-version, nextest-version, cargo-check, nextest-list, and nextest-run. The frozen nextest version remains 0.9.137. Original version/check/list/run timeouts, total budget, jobs=2, complete case and ignored inventory comparison, exact retained test-binary identities, no retries, original-child wait/reap and group-absence checks, and INT120/TERM10/KILL10 cleanup are unchanged.

Install the actual six-file CI tools inventory separately at `ROOT/rust-ci-tools-01`, the exact parent at its bound path, and the qualification bindings at `ROOT/rust-ci-qualification-bindings-01.json`. After that, the original native launch is:

```text
/usr/bin/python3 -I -B ROOT/rust-ci-tools-01/launch_exact_rust_ci_01.py --launcher-sha256 ACTUAL_SEALED_LAUNCHER_SHA256
```

Use cwd ROOT, empty explicit env, timeout 6600 seconds, and one stable original request key. The launcher creates the fresh plan, then execs the reviewed runner. Preserve the actual native terminal status, complete original reads, plan, report, nextest audit, and stage streams. Successful local sealing or external exact CI would not establish hosted Actions success, performance improvement, or candidate adoption.

## Present evidence boundary

Only source comparison, AST parsing, metadata identities, and guard-order inspection were performed for this package. The original scripts were not imported or executed. Independent review `e7c21342c3a9f75171b14be858a925d7876745d6` covers the four derived scripts and their narrow differences. The final parent source and actual qualification data remain prerequisites for sealing.
