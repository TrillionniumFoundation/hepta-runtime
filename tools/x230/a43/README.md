# A43 A46/A47 evidence and exact historical helpers

These files accompany [the executed result](../../../docs/experiments/x230/a43-a46-a47-results.md)
and [machine-readable summary](../../../docs/experiments/x230/a43-a46-a47-summary.json).
The [evidence manifest](../../../docs/experiments/x230/evidence/a43-a46-a47/manifest.json)
identifies a deterministic lossless archive of five original records, plus the
complete qualified-source Git-object proof and pinned GitHub tree comparison.
The archive retains original JSON/log bytes; no report was compacted, redacted
or relabeled as an independent run. It contains owned synthetic-fixture process
samples, nonsecret identifiers and test/bootstrap snippets. The audit found no
authentication credentials, private keys, unrelated host inventories or compiled
executable bodies. Missing referenced sidecars are explicitly listed in the manifest.

## Read-only recomputation

From a checkout containing this publication:

```sh
python3 tools/x230/a43/recompute_a46_a47.py --source-root .
```

This reads the archive without extracting files, verifies compressed/member
SHA-256 values and recomputes test counts, the actual SIGKILL/restart boundaries,
128 original supervisor completions and the pooled metrics. `--source-root .`
also hashes all 166 prepared-source members against both their SHA-256 and
body-derived Git blob IDs. Omitting that option leaves
`source_bodies_rehashed=false`; it does not silently claim a checkout audit.
The verifier makes no network, SSH, subprocess, process-signal or workload calls,
and writes no result files. It does not rehash executable bodies or complete
resource-gate sidecars, which are not included. A passing recomputation verifies
archived evidence and arithmetic, not performance superiority or production adoption.

## Frozen execution code

| File | Role | Exact SHA-256 |
| --- | --- | --- |
| `qualify_a43_a46.py` | Actual new six-stage A46 entry and strict fresh-artifact wrapper | `7ce825966b413ab5e2d31979fbd5bb0e47a67a9105827d742ea986124610b176` |
| `prepare_qualify_a44_owner_barrier_r01.py` | Original source validation, six-stage guard and original-child custody code reused by A46 | `84e5fc48a688f83987425ff357428230083948703d419db4be1227d6b1ed8113` |
| `a44-owner-barrier-qualification-r01.protocol.json` | Immutable original policy verified before the new A46 bindings | `45185065cf0540296ea722bdfd4f000940338e466a6c936dfd34ca7cdbc5d50b` |
| `qualify_runtime_candidate.py` | Unmodified 5,915-byte Cargo qualifier; identical to the existing A40 helper | `64efa0da0d22e2ad8d10eb6f8a91ab158a234b331383bbd595e65fc9bd47d1d2` |
| `run_a41_native_validation_r07.py` | Frozen qualification/source/host-observation helper imported by the run scripts | `6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9` |
| `validate_owner_lifecycle_a47.py` | Actual 46,020-byte A47 source-extracted owner lifecycle and ABBA harness | `a6672e5ebe87fd0fda7ded00b72b9f1c6213eedb952fb9be9b6a7c6e99367455` |

These are exact historical bytes. Their fixed X230 development paths, source
bundle bindings and attempt identities are intentionally retained for review.
They are not portable one-command replay scripts, and their historical output
paths must not be reused. The original source-bundle body, complete host-gate
sidecars and executable binaries are not bundled here; their retained bindings
remain in the reports. A later experiment needs its own fresh source/output
bindings and actual admission/evidence, while the old execution stays unchanged.

No A42 or A48 source overlay is part of this publication. The only source edit
above the A43 checkpoint is the exact formatter output for
`jobs_owner_publication_tests.rs`; the source-object proof covers all 166 inputs.
