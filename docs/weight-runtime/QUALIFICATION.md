# Weight runtime qualification

Qualification date: **2026-11-03**. This document records the isolated research
runtime's engineering checks. It does not report model-performance improvements,
private evaluation results, or production approval.

## Qualified package and default state

The final Python worker package is bound to:

```text
package SHA-256:
4ea015d5844e5b4d2df4025b39aad39f5a7e96a44952e507e857add2d9fd100e

worker.py SHA-256:
10c09efcb24d65ce850ccbee61f3034262fa026ee5d19adab90bc9eda67049c0
```

The package hash covers `worker.py` and the runtime Python modules according to the
canonical algorithm in [the worker protocol](../../workers/weight/PROTOCOL.md).
Documentation and tests are outside that package digest. The entry hash alone does
not bind imported modules. These hashes detect drift from admitted code; they are
not publisher signatures.

**`weight_workers` defaults to an empty map.** Without configured profiles, the six
weight tools are absent from MCP discovery. This delivery has **not enabled
production weight profiles or activated a production model**. Research sealing
does not authorize model promotion, and `production_eligible` remains false.

The Rust integration uses the existing durable process owner for execution,
resource limits, status, cancellation and log capture. **No Cargo dependencies
were added.** Configuration and ownership details are in
[RUST_OWNER.md](RUST_OWNER.md).

## Final validation and evidence binding

The final worker package above was exercised on an owned Linux CPU host with real
PyTorch, real Unix sockets and the actual stdio MCP binary. The CPU environment
used Python 3.12.3, PyTorch 2.6.0+cpu, NumPy 2.2.6 and safetensors 0.5.3.

| Check | Qualified result | Evidence version |
| --- | --- | --- |
| Python worker suite | **38 passed, 0 skipped** | v5; final package |
| Real resident-worker MCP integration | **1 passed, 0 failed, 0 ignored** | v5; final package |
| Rust formatting | `cargo fmt --all -- --check` succeeded | v4, bound to unchanged Rust sources |
| Rust lint | `cargo clippy --locked --all-targets --all-features -- -D warnings` succeeded | v4, bound to unchanged Rust sources |
| Full Rust suite | **422 passed, 0 failed, 16 ignored** | v4, bound to unchanged Rust sources |

Before reusing the v4 Rust checks, v5 compared the SHA-256 of **all 53 Rust source
files** and found no changes. The final worker required fresh Python and real MCP
checks; those were rerun. The source manifest was unchanged during v5 validation,
and the shared source copy matched the qualified host snapshot. The retained v5
record binds the reused v4 report by its SHA-256 instead of claiming that unchanged
Rust gates were rerun.

The 16 ignored entries in the ordinary Rust suite comprise 15 pre-existing external
tests and the new resident-worker MCP test. The new test was **separately executed
with `--ignored`** and passed against the final worker package. An ignored test is
not counted as a successful external validation.

## What the real MCP test establishes

[The external test](../../tests/weight_mcp_external.rs) uses a synthetic 2×2
safetensors model and the shipped stdio MCP binary. Its calls traverse the existing
SSH durable-job owner, a resident PyTorch worker and actual AF_UNIX clients.

The test establishes that:

- An admitted model worker returns a real model-open result through retained logs.
- Restarting the MCP controller recovers the original resident job.
- An identical request ID reuses its original client job and result; changed
  content under that ID is rejected.
- Replaying the probe leaves the cumulative forward count at one, and artifact
  query returns the expected synthetic output.
- Active-session admission respects the configured capacity.
- Closing a session is followed by an observed terminal state; the closed identity
  cannot relaunch a worker.
- The source model file's SHA-256 remains unchanged.

The test prints a machine-readable qualification receipt binding the model,
worker package, original-job reuse, forward count and observed terminal state.
Environment-specific execution receipts remain outside the public source tree.

## Seven resolved engineering issues

| Issue | Implemented correction | Regression coverage |
| --- | --- | --- |
| **1. Favorable observed rows could yield positive confirmation while frozen confirmation samples remained pending or censored.** | `paired_eval` requires the frozen confirmation population to be complete before a positive confirmation. Pending and censored outcomes remain explicit unknowns; they are not scored as losses or silently discarded to confirm a favorable subset. | [The paired evaluator](../../experiments/weight/evaluation/paired_eval.py) and its [14-test suite](../../experiments/weight/evaluation/test_paired_eval.py) cover incomplete confirmation, censoring, identity bindings and outcome timing. |
| **2. Failed initial or recovered open could retain a callable provider or reset consumed budgets.** | Recovery verifies model, backend and open-spec identities and restores spent forward/patch budgets before loading. Every failed admission detaches provider/store/policy state, including cleanup failures. Unresolved operations retain their unknown outcome and block new computation. | [Transport regressions](../../workers/weight/tests/test_transport.py) cover failed admission and replay, identity drift, cleanup failure, preserved exhausted budgets and unresolved-operation holds. |
| **3. A crash between hard-link publication and staging cleanup could leave a two-link Rust record that its reader rejected.** | Publication now uses Linux `renameat2(RENAME_NOREPLACE)`, so the completed namespace transition leaves one link. Existing records remain immutable, and arbitrary additional hard links are still rejected. | [Rust tests](../../src/mcp/weight_tests.rs) exercise publication before directory sync/acknowledgement, recovery of the original record, replacement refusal and the single-link check. |
| **4. A legacy replay import could combine individually valid but unrelated candidate, source, label or calibration records.** | The importer cross-binds the sealed candidate, source plan and records, outcomes and labels, input/prediction digests, and frozen calibration identity and application. Recomputed scores cannot substitute for those lineage checks. | [The replay importer](../../experiments/weight/evaluation/replay_laya.py) has [19 synthetic regression tests](../../experiments/weight/evaluation/test_replay_laya.py) covering cross-candidate/source/label substitution and frozen-calibration mismatches. |
| **5. A nominal RowLoRA effective-weight no-op could change actual FP32 execution when its factors were reconstructed.** | An exact effective-weight no-op preserves the original A/B tensors and nested execution. Realized effective FP32 changes and stored-parameter changes are reported separately. | [Laya adapter tests](../../workers/weight/tests/test_laya_adapter.py) verify preserved factors and actual nested forward output for a no-op, realized effective changes and restoration of the original parameters. |
| **6. Localization evidence could be handed to an edit run with different rows, model, backend or encoded model inputs.** | Localization and editing bind the same rows digest, model identity and backend identity. Probe handoff also checks row/order/layout/state lineage and requires the edit run's actual `model_input_id` to match the retained localization input. | [Four lineage tests](../../experiments/weight/test_laya_lineage.py) cover exact matches, cross-input/model/backend rejection, probe alignment and refusal of old unbound summaries; the checks are enforced by [the experiment driver](../../experiments/weight/laya_session_experiment.py). |
| **7. Laya input serialization could use retained JSON key order instead of the production encoder's field order.** | The adapter rebuilds state in the pinned dataset's `CAUSAL_STATE_FIELDS` order before encoding. `make_laya_encoder` is shared with the dedicated parity checker, so order handling is checked at the input-tensor boundary. | [Encoding tests](../../workers/weight/tests/test_laya_encoding.py) cover field-order invariance and validation. [The tokenizer-only checker](../../workers/weight/tests/check_laya_encoding.py) supports exact comparison with the installed production encoding path without loading model weights or running a model forward. |

Additional [transport regressions](../../workers/weight/tests/test_transport.py)
cover preservation of stricter owner thread limits and clean JSONL stdout with
Python, direct native and buffered native logging.

The preprocessing correction changes which input tensors reach the model. Results
from earlier adapter versions therefore cannot be substituted for evaluations of
the final qualified package. Engineering qualification also does not establish
predictive usefulness or a valid production candidate.

## Reproduction boundary

Run the normal Rust gates from the repository root, then the Python suite in an
already-provisioned compatible environment:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
python -m unittest discover -s workers/weight/tests -v
```

Run the real MCP test with the explicit environment variables documented in
[RUST_OWNER.md](RUST_OWNER.md). It requires an authorized localhost SSH identity and
a real CPU Python environment; the test does not install dependencies or relax the
existing owner's host policy. AF_UNIX skips in a restricted development sandbox
must be reported and resolved by an actual permitted-host run, as they were for
this qualification.

These checks qualify the isolated Linux research interface and its recovery,
ownership, serialization and preprocessing contracts. Production profile admission,
independent candidate evaluation and model activation remain separate owner
decisions.
