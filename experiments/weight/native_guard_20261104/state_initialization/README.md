# Private state creation on first startup

**Status: the focused first-start fix is validated. No complete-suite pass is
claimed by this followup.**

The controller could accept a valid configuration with a missing state directory,
create that directory with mode **0755** under the CI umask **0022**, and then
refuse the first tool call because request auditing requires the same root to be
exactly **0700**. This followup changes the creation mode of newly created state
directories. It preserves the existing external test inputs and assertions.

The [production initializer](../../../../src/mcp/runtime/config.rs) now uses a
recursive `DirBuilder` with Unix creation mode 0700. Existing directories retain
their permissions. Canonicalization, controller ownership, group/world-write
rejection and the exact-mode audit admission rule remain in place.

## Evidence and scope

The two failures occurred in both the
[old base CI](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/41692021906/job/126112746047)
and the
[first exact-head CI for this PR](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/41794981838/job/126456845758).

Both failed at `tests/rea_mcp_external.rs:88:13`, with JSON-RPC error
`-32603: request audit unavailable; dispatch refused`:

| Existing integration test | First rejected request | Intended first operation |
| --- | ---: | --- |
| external_mcp_policy_worker_and_controller_restart | 3 | rea_inspect_artifact |
| model_pages_ranges_and_archive_roles_use_the_shipped_mcp_workers | 20 | rea_inspect_model |

These are the first positive tool calls. The error occurs in audit admission
before the tool handler is dispatched. The failures therefore do not establish
a REA parser, model paging or retained-evidence defect.

The historical CI error message normalizes the underlying audit error, and the
external fixture discards controller stderr. The original CI directory metadata
was not retained. The exact mode was subsequently observed in a separate,
bounded reproduction of the same valid first-start input; this distinction is
retained in [qualification.json](qualification.json).

## Why this required a production fix

The existing [configuration regression tests](../../../../src/mcp/runtime/config_tests.rs)
include `installed_policy_digest_child_probe`. It supplies a newly absent
`normalization/../state` path, calls `init_runtime` and checks the canonical
installed path. A missing state directory is a valid startup input.

Before the fix, `init_runtime` used `create_dir_all` and accepted roots that were
not group/world writable. It then made only the `jobs` and `audit` subdirectories
0700. The controller-owner check managed the lock files; it did not tighten the
root mode. Under umask 0022, the new root could consequently be 0755.

The [audit implementation](../../../../src/mcp/runtime/request_audit.rs) obtains
its root from `runtime_config.state_dir`. Its final-directory check requires
mode 0700, the current owner and a real directory. The permissive startup creation
and the stricter first-request requirement were inconsistent.

Precreating the directory inside the external tests would hide this valid
first-start failure. The external fixtures were therefore left byte-identical.
The earlier library-only test repairs for directory publication and maintenance
isolation do not change this external controller initialization path.

## Controlled validation

Every focused execution used the recorded umask 0022, NOFILE soft limit 1024,
one test-harness worker, and a private 0700 temporary root outside the worktree.
The temporary root used a 16-byte path. Controller observations cleared the
environment, matching the existing external fixture.

| Validation | Result | Recorded execution time |
| --- | --- | ---: |
| Unchanged external test binary against the old controller, both original tests once | Exit 101; 0 passed, 2 failed; same IDs and audit error | 0.065085 s command; 0.04 s harness |
| Old controller, separate missing-state observation | Initialize succeeds; root is 0755; first tool is refused | 0.044421 s |
| Focused rebuild of library and external test targets, no test execution | Cargo 0 | 166.542417 s |
| Same external test binary against the fixed controller, both original tests once | Exit 0; 2 passed, 0 failed | 3.925748 s command; 3.90 s harness |
| Existing configuration regression module | Exit 0; 20 passed, 0 failed | 0.032815 s command; 0.02 s harness |
| Strict all-features, all-targets Clippy | Exit 0 | 46.991213 s |
| Formatting checks before and after | Both exit 0 | 2.722781 s and 2.673145 s |
| Fixed controller, newly absent state | Root becomes 0700; first REA inspection succeeds and reports WASM | 0.312809 s |
| Fixed controller, pre-existing 0755 state | Root stays 0755; first request retains the exact audit refusal | 0.017781 s |

The existing-directory negative control checks the security boundary directly:
the fix does not chmod an existing root or permit a previously refused root.
The two mode observations had 30-second limits and their owned controller
processes were reaped after observation. Their intentional process cleanup
signals are recorded separately from the semantic observation results.

The external test executable itself remained byte-identical across the baseline
and fixed runs:

```text
f2da4ae78f302b61330a4e82231e4a46fde33b12eba7f9d0d055ab794ae49284
```

The controller changed from:

```text
61170e9ba6c6cd17d907f11e2c3e3b01e59d3855ca3ab11de26205c8ba996228
```

to:

```text
c60edb53b18c6781f227b51f00b1c049dd997fe8d3a430a12b819f982910f9f6
```

This comparison preserves the original tests, their first-start inputs and their
assertions while changing the production initializer. The complete existing
external tests also exercise the later parser, paging, range, retained-evidence
and controller-restart assertions; they were not replaced by a reduced smoke test.

## Source and evidence identities

| Item | SHA-256 |
| --- | --- |
| Initializer before | b772110a05c16204928144a900c75b609f296b4c7e26f216b293810d481c31e2 |
| Initializer after | f2f37d2b5b7f25a704a75651ae0e0a9044796dbfebd33dd72f901c259850c3f9 |
| Unchanged external fixture | 53a53d5da2877274bb9c75ddf6fbde9371f5d38b56d90bde4376f90de5c8d0cd |
| Unchanged configuration regression source | 533962981326e05fbfc1b7f6ce1986df804916c88ff67c0cbe38926d3d2a5f69 |

The initializer before the edit was byte-identical to local commit
`bdb2eaa675757502be19647b11a83f03bb972a11`, whose tree matched published head
`f63aa5c750ec7d2d537e50c22ef0b1bc8cc6814d`. A second reviewer independently
reconstructed the single source change and obtained the exact after hash.

All 50 original publication payload files and their original publication
manifest—51 files total—were verified unchanged before the edit and through
the final validation. Their identities are retained in the receipt. The
publication owner will add this followup and update the enclosing manifest
after these gates; that later publication update is separate from validation.

Raw test and controller logs remain on the authorized validation host. Their
full byte sizes and SHA-256 values, exact command options, step return codes,
source identities and timing records are preserved in qualification.json.
Private absolute host paths, process identities, model weights and individual
trading records are excluded.

## Reproduction

Use the recorded source and locked dependency cache. The receipt records the
exact build and frozen-binary commands used for the comparison. The ordinary
Cargo equivalents for the unchanged test bodies are:

```sh
qualification_tmp="$(mktemp -d /tmp/hw-XXXXXXXX)"
chmod 700 "$qualification_tmp"
export TMPDIR="$qualification_tmp"
export CARGO_BUILD_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
umask 022
ulimit -Sn 1024

cargo test --locked --offline --all-features --test rea_mcp_external -- --test-threads=1 --nocapture
cargo test --locked --offline --all-features --lib mcp::runtime::config::tests:: -- --test-threads=1 --nocapture
cargo clippy --locked --offline --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```

Record each command's actual return code independently. A wrapper's final status
does not replace the test command's code. The two controlled directory-mode
observations are separately recorded diagnostic cases; they are not added to
the 22 passed tests.

## Qualification limits and cost

The recorded focused command and bounded observation timers sum to
**223.328217 seconds**, including the focused rebuild. The baseline runner's
0.920268-second duration also includes its metadata and copy work; it is retained
separately and is not added again. These values are verification wall times,
not CPU/GPU use, a model-training benchmark or total project elapsed time.

The [original r8 qualification](../qualification.json) remains failed:
Cargo 101, 1694 passed, 2 failed and 36 ignored. Its two index failures are not
explained by this state-initialization repair. The first official exact-head CI
also remains a recorded failure: nextest exit 100, 1762 passed, 2 failed and
40 skipped. No complete suite was rerun for this focused followup. Any subsequent
official CI result belongs in a separate exact-head record.

No trading operation, broker request, model training or model-quality experiment
was performed in this followup.
