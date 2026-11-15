# R21 campaign evidence capture and offline replay

These tools prepare one evidence archive and one reproducible local replay.
They do not run a runtime, workload, compiler or SSH operation. Preparing them
does not assert that the future R21 campaign has passed. Run the exporter only
after the actual campaign has reached a terminal state and its owned local
children have exited.

## Capture boundary

`export_campaign_01.py` snapshots all regular files, including arbitrary raw
filenames and failed attempts, beneath these four X230 directories:

- `campaign-control-01`
- `native-observation-01`
- `native-boundary-01`
- `lifecycle-abba-01`

There is no extension or filename filter within those trees. Native transport
frames, resource traces, stdout/stderr, SSH replies, controller configuration
and job state, per-phase CPU sidecars, original independent summaries and
failure records remain intact. Empty-directory identities are recorded. The
exporter checks directory membership and stable complete file identities
again after packing.

A successful campaign archive also includes the frozen 25-file campaign,
boundary and lifecycle installation; the original R16 measurement and boundary
tools; plan; component chain and its nine actual inputs; referenced R19/R21
qualification proofs; qualification tool sources and control streams; profile
template; topology; and the six original job records. Fresh profile JSON,
rewritten SSH configuration and known-host files are already within the raw
trees. No SSH agent, private key or unrelated credential file is opened.

Only these nine ELF bodies are excluded:

- Three executed copies in R19 `qualification-02`.
- Three copies in R21 `qualification-01`.
- Their three exact R21 `target-fresh-01/release` counterparts.

Each receives a complete SHA256, byte count and stable metadata witness. Only
the three explicit compiler-target paths may have stable hardlinks. Ordinary
inputs and executed copies retain the single-link rule. A log named
`binary.stdout` or any similar raw filename is not an exclusion. The exporter
does not traverse a compiler target tree.

The Mac holder's source, terminal report, forwarded logs and agent-cleanup
receipts are outside X230. Root must close them in a separate holder/local
evidence package. This archive explicitly says they are not included.

## Failed terminal campaigns

A terminal `passed: false` campaign uses a separate capture branch. It retains
the safely readable raw trees even if a frozen dependency is missing, changed
or no longer agrees with qualification. Fixed source paths are used; changed
manifests and arbitrary chain references are never executed or followed.
Dependency errors are listed as `identity_errors`, and qualification validation
is explicitly false. Available ELF identities remain path-excluded witnesses,
with no assertion that they still equal accepted qualification.

Missing stages remain missing; no synthetic empty successful output is added.
If a primary raw tree itself cannot be enumerated safely or a raw file changes
while read, the exporter keeps its error receipt and any partial output and
fails. It does not describe an incomplete or unsafe raw snapshot as complete.
No attempt is deleted or retried automatically; a manual later export needs a
new `export-campaign-NN` directory.

## Installation and invocation

Install the files in `evidence-tools-manifest-01.json` and the manifest beneath
`/home/qian/hepta-runtime-optimization-20261105-r21/evidence-tools`. The manifest
does not contain itself. The fixed campaign and lifecycle manifests remain
separate inputs and are not modified.

After the campaign closes, supply the actual original report SHA256, actual
qualified candidate ELF SHA256 and this evidence-tools manifest SHA256:

```sh
python3 -B /home/qian/hepta-runtime-optimization-20261105-r21/evidence-tools/export_campaign_01.py \
  --expected-campaign-report-sha256 "$R21_CAMPAIGN_REPORT_SHA" \
  --expected-candidate-sha256 "$R21_CANDIDATE_ELF_SHA" \
  --expected-evidence-tools-manifest-sha256 "$R21_EVIDENCE_TOOLS_SHA" \
  --out /home/qian/hepta-runtime-optimization-20261105-r21/export-campaign-01
```

The output consists of `campaign-evidence-01.tar.gz`, `manifest.json` and
`receipt.json`. The embedded `_export-manifest.json` is byte-identical to the
external manifest and is the archive's first member. Gzip/tar timestamps and
ownership fields are deterministic. The source files are never rewritten.

Transfer the original archive and receipts with the existing versioned binary
reader. Bind the observed version, complete byte count and SHA256. Record actual
piece sizes, failures and any same-byte retry; do not infer a chunk limit from
another transfer. No transfer or network operation is implemented here.

On the local machine, pass the observed archive and manifest hashes and use
two fresh, nonoverlapping directories:

```sh
python3 -B replay_campaign_01.py \
  --archive "$R21_RECEIVED_ARCHIVE" \
  --expected-archive-sha256 "$R21_ARCHIVE_SHA" \
  --expected-manifest-sha256 "$R21_ARCHIVE_MANIFEST_SHA" \
  --expected-campaign-report-sha256 "$R21_CAMPAIGN_REPORT_SHA" \
  --expected-candidate-sha256 "$R21_CANDIDATE_ELF_SHA" \
  --extract-root "$R21_FRESH_EXTRACT_ROOT" \
  --output-root "$R21_FRESH_REPLAY_ROOT"
```

The replay validates every member before creating the extraction tree, rejects
links, path escapes, duplicates and extra/missing entries, then restores the
original bytes. It retains a failed campaign's restored evidence even if its
subsequent fixed-tool or audit gates reject it. No original summary is replaced.

## Seven original offline entries

The replay runs the exact archived sources, with their original interfaces:

| Entry | Frozen tool | Input |
| --- | --- | --- |
| Native | `analyze_native_observation.py` | Native report and all retained raw frames/traces |
| C32 boundary | `audit_native_boundary.py` | Boundary report, original capacity policy and frozen harness root |
| Lifecycle 0-A | `verify_cancel_recovery.py` | Original round report and full raw evidence |
| Lifecycle 1-B | `verify_cancel_recovery.py` | Original round report and full raw evidence |
| Lifecycle 2-B | `verify_cancel_recovery.py` | Original round report and full raw evidence |
| Lifecycle 3-A | `verify_cancel_recovery.py` | Original round report and full raw evidence |
| Lifecycle aggregate | `summarize_lifecycle_abba_01.py` | Closed round index and all 44 phase sidecars |

Each runs with a fixed 180-second limit, retained stdout/stderr, child wait/reap
and no retry. The first six use `--report`; the last uses the original `--index`
option. Every newly generated analysis must equal the archived original JSON
object. These are offline audits; the lifecycle workloads are not run again.

The native gate and adjacent-pair views are computed by extracting the four
pure definitions `need`, `finite_positive`, `native_decision` and
`native_metrics` from the exact frozen campaign source. The workload module is
not imported and no new statistical definition replaces the original one.

## Denominators and interpretation

Native full-protocol counts are 2,304 measured calls, 288 warmup calls and 72
preflight/restart calls, or 2,664 total. Warmup and all 72 extra calls stay out
of the performance denominator. Any actual count deviation is retained and
fails the fixed-protocol check; it is not normalized away.

For each C1/C8/C16 case, the original analyzer divides all measured successful
calls in an arm by the sum of that arm's cell windows. It does not average
round rates. P95 is the original nearest-rank statistic over all that arm's
raw measured latencies. The screen remains rate B/A ≥0.95 and pooled p95 B/A
≤1.10. P99 and the two adjacent A/B comparisons remain visible without adding
a new gate.

C32 retains 64 attempts across two bursts. Successes, exact internal capacity
refusals and other errors remain separate. Refusal never contributes to a
successful-throughput numerator, and no fixed 16/16 split is imposed.

Lifecycle fixed effects are 24 new starts, 48 same-key lookups and 48
cancellations over four C6 rounds. Its original bounded polling remains in the
raw evidence; total native RPC count is observed rather than forced to 90 per
round. Phase wall time includes the original confirmations, polling and SSH
inspections. Controller CPU uses the existing same-PID/start-ticks counters
bracketing each phase and excludes SSH/remote CPU; preparation has no active
controller CPU measurement.

RSS and IO retain the original sampled controller/tree observations and all
recorded errors. The replay creates no per-call RSS attribution, new peak
estimator or synchronized cluster-total metric. The excluded ELF bodies cannot
be independently rehashed locally: their remote complete-hash witnesses and
archived proof bindings are checked, and that limit remains explicit.

An export receipt's `passed` means a stable archive was produced. A replay
report's `passed` means the complete original audits and deterministic
cross-checks agree. `native_regression_screen_passed` remains separate and may
be false even when the evidence replay succeeds. Neither tool makes an adoption
decision or claims statistical significance, global optimality or maximum
sustainable launch throughput.
