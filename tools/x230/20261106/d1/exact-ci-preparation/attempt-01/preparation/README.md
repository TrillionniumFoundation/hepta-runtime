# D1 exact Rust CI preparation

This is an unsealed preparation of the same external Rust CI protocol used by the completed R35 attempt. It cannot launch CI until the original D1 qualification has actually succeeded and its original receipts, final 222-input map, full test inventory and dynamic counts have been bound. No CI, Cargo, formatter, Rust test, host API or remote command has been run while preparing this directory.

## Original protocol and six-tool package

`references-r35/` contains the exact six tools from the actual R35 sealed tree `a39e0e61163bb5780685fcbc1c9db1fefa2a97e4`, plus its three original sealing references. Every recovered byte stream was checked against its Git blob and SHA256. The nextest auditor and the 7,631-byte canonical workflow are copied unchanged.

The generated `unsealed-tools/` has the original six-file layout:

- `materialize_rust_ci_plan_01.py`
- `run_rust_ci_01.py`
- `audit_nextest_0137.py`
- `canonical-workflow.yml`
- `package-manifest-01.json`
- `launch_exact_rust_ci_01.py`

The complete runner differs only in the D1 namespace and host root. Its original subprocess identity, stream capture, deadlines, signal escalation, wait/reap, process-group closure, source recheck and error behavior remain intact. The launcher also retains its original materialize-then-exec sequence. The original CI manifest, pinned nextest 0.9.137 executable and installation receipt remain unchanged.

The exact commands remain:

```text
cargo check --locked --all-targets --all-features
cargo nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast
```

The original unfiltered structured inventory command also remains:

```text
cargo nextest list --locked --all-targets --all-features --message-format json
```

The six original stages are Cargo version, Rust version, nextest version, Cargo check, nextest list and nextest run. Case selection, complete ignored set, exact case inventory, zero retries, single test thread, stage timeouts and parent cleanup are unchanged. CI retains offline execution through the original environment, with the published workflow's exact command arguments. This is external command evidence and does not mark hosted GitHub Actions as passed.

## Q-only foundation without a circular CI dependency

The materializer reads the separately pinned module at:

```text
/home/qian/hepta-runtime-phase-cost-20261106-d1/rust-ci-prerequisites-01/d1_prerequisites.py
```

This module is outside the original six-tool directory, so the launcher inventory is not expanded. The module is imported without calling a main entry point. Its `checked` callback preserves the existing file identity ABI. Its `bind_d1_qualification(prerequisites, bind)` returns the original proof fields `passed`, `original_job_id`, `qualification`, `preparation`, `terminal`, and `tests`.

The input is `ROOT/qualification-prerequisites-01.json`, schema `hepta-d1-c1-prerequisites/v1`, with `qualification_sealed=true` and `exact_ci_sealed=false`. It binds the real original qualification inputs and all native read pages. CI does not depend on the future CI report or on a started diagnostic campaign. The later full parent uses its separate prerequisite input with both completed qualification and CI bindings.

The foundation checks the actual completed preparation and cache transfer through their original receipts. It must not rerun the preparer's pre-rename R35 cache check after that cache has been renamed. Both the module itself and all files it reads enter the original materialized plan's input bindings and are rechecked by the original runner.

## Feature and source scope

D1's original qualifier uses `--all-features`. The CI commands above therefore test the same diagnostic-feature-enabled source. The original environment scrub removes `HEPTA_*` from CI children; diagnostic mode is not enabled by this package. The ordinary feature-off supplemental qualification is a separate step and cannot replace these exact workflow commands.

The source check changes from 220 to 222 compiler inputs. The same original 19 harness files and all eight successful qualification stages are required. The final formatted map is taken only from actual qualification artifacts, with the same 13 allowed changed paths and 209 unchanged R24 inputs. Counts are read from the completed isolated summary and its independent audit. No count is predicted from the number of new test functions.

The canonical workflow is the original 7,631-byte published workflow. The 7,235-byte private workflow copied with accepted R24 source remains separately bound and is not rewritten. The original CI manifest's full input closure and workflow Git blob remain part of the materialization proof.

## Sealing

`actual-pins.unsealed.json` names the 12 required original inputs. All future qualification job/result/map/count/ELF values remain absent. The materializer's actual qualification constants are `None`; the launcher has `SPEC=None`. Their original guards reject before plan publication or child creation.

After the root agent has collected the real completed qualification originals and the reviewed Q-only foundation, it may fill a new actual-pins file and run this local data-only sealer:

```text
/usr/bin/python3 -B seal_exact_ci.py --pins <actual-pins.json> --output <new-sealed-directory>
```

The sealer validates the local original bytes, original successful native terminal flags, original eight-stage report, formatter map, preparation, dynamic isolated counts and independent audit. The isolated audit uses `hepta-isolated-libtest-audit/v1` and `success=true`; it is distinct from the nextest auditor's `verified` field. The detailed live source and native-page checks remain mandatory in the same Q-only foundation before the materializer can publish a plan.

The sealer creates the six tools, the exact independent foundation bytes, Q-only prerequisites, original supplied pin file, seal manifest and launch command in a fresh directory. It does not execute the materializer, CI runner, foundation's host-reading binder, Cargo or any test. The original unsealed package remains unchanged.

Install the sealed six tools as `ROOT/rust-ci-tools-01/`; install the foundation as `ROOT/rust-ci-prerequisites-01/d1_prerequisites.py`; install the exact Q-only prerequisites as `ROOT/qualification-prerequisites-01.json`. The final command is the original launcher with its actual SHA256. `ROOT/rust-ci-plan-01.json` and `ROOT/rust-ci-01` must be absent. The root agent alone controls actual installation, one native CI invocation, original terminal/read capture and any subsequent measurement.
