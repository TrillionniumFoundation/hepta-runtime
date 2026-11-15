# R34 observation archive recovery 02

The first archive attempt failed before creating any archive or sidecar. Its
collector had incorrectly inherited three hashes for R33's materialized
lifecycle tools. The R34 measurement, qualification, CI and rejection are
unchanged. This recovery corrects the archive bindings; it does not rerun a
measurement, lifecycle materializer, compiler, benchmark or original auditor.

## Original failure retained

Original job `1a1af44cd02-fc05-6739` finished failed, exit 1. Its complete,
durable streams are stdout 0 bytes and stderr 42 bytes:

```text
ValueError: frozen original input differs
```

The original frozen collector remains 59,309 bytes, SHA-256
`dfe08662dd65995a0e27edc6c06bf4e1754a1fc936a81c10657f2ff4e8c1695b`,
Git blob `f837d6b053573445065a7e9e5729cc40ccdb9873`. Its first review and all
original preparation files remain preserved. The initial source review checked
safety deltas and six local originals, and did not identify these three
inherited hashes. It did not claim that all remote inputs had been read.

Read-only diagnostic job `1a1af47b4a8-fc05-674c` completed successfully, with
complete stdout 1,533 bytes / stderr 0 bytes. Its original 44,679-byte report
has SHA-256
`a30b955e31f142c7e833c006138bc434e14e1c4eda3bb8bb11bb211de528cb30`.
It checked all 99 original pins: 96 match, and exactly the following three do
not. It also observed all three first-attempt archive output paths absent.

## Cause and independent provenance

The original R34 installer explicitly changes one output-root constant in
`run_lifecycle_abba_01.py` and `run_six_host_cancel_recovery_timed.py`, then
canonicalizes their manifest. The collector's inherited R33 pins therefore
describe the wrong round's two already-materialized scripts and manifest.
The installed R34 files had not drifted.

Both evidence reviewers independently read the preserved R33 archive in
bounded memory without extracting or executing contents. The evidence-review
agent reversed each single R33 root constant to R29, matched both original
R29 source hashes recorded in the original install receipts, and reconstructed
the exact R29 manifest SHA required by the frozen R34 installer:
`a377791a94e1327bdf3c7da98f30b379caafe6948295d81871f06287bf7c5ef0`.
Applying only the installer's declared R29-to-R34 root substitution produces
the following identities. They also exactly match the original R34 install
receipt and the separate actual stable-read diagnostic.

| Original installed R34 file | Bytes | Correct SHA-256 |
| --- | ---: | --- |
| `lifecycle-tools-01/run_lifecycle_abba_01.py` | 14,787 | `3ae83b59414edd39f98f489ea0e60722bd59715e782a30b1f47a323460e48fff` |
| `lifecycle-tools-01/run_six_host_cancel_recovery_timed.py` | 30,163 | `e0f2f2bc9e3656da2d941936f572d24001a340c4ab6219de37991b998ef21a86` |
| `lifecycle-tools-01/lifecycle-tools-manifest-01.json` | 4,066 | `86522df4c3a9870bc877f208f774c4f7e8cafc9560df658dd8048b3700be1c40` |

The original install receipt is 26,390 bytes, SHA-256
`b783a85e4b41e5202305b7739e63eace75c71d4ea65f14fcbe7d05e5ceef30a2`.
Recovery does not accept a changed live file merely because it currently
exists; the original installation, deterministic source transformation and
actual diagnostic all agree.

## Minimal collector change

`sealed-02/archive_r34_observation_02.py` changes the three fixed hashes and
uses the fresh `observation-evidence-02` output stem. It additionally retains
the original archive failure native/read and original pin-diagnostic report,
and crosschecks their correction rows against the original installer and
archived file bytes. The original 29 dynamic observation bindings are
unchanged. All functions other than summary/creation are byte-identical to
collector01; creation changes only the output stem. No guard or bound is
weakened. Limits stay 64 MiB total, 8 MiB per file, 2 MiB manifest and 8,192
files, with zero-extraction verification and no archived-program execution.

The required existing remote recovery originals are:

- `ROOT/observation-archive-native-failed-01.json`
- `ROOT/observation-archive-read-failed-01.json`
- `ROOT/observation-archive-pin-diagnostic-01.json`

The diagnostic native status/read, diagnostic script and original install
receipt also remain in the public evidence catalog. Collector01 source is
preserved by its original Git blob and source package; it is not rewritten.

After root reviews the exact collector02, its single invocation is:

```text
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261106-r34/archive_r34_observation_02.py --kind observation
```

The only new outputs are `observation-evidence-02.tar.gz`,
`observation-evidence-02.manifest.json` and
`observation-evidence-02.compact.json`. They are exclusive creates and have no
automatic retry. Their actual identities must come from the original native
archive job; no future archive success is filled into this preparation.

## Local preparation boundary

The first local source-generator call used the key `report` while the actual
diagnostic stdout uses `receipt`; it stopped with `KeyError` before creating
the sealed output directory. That local field lookup was corrected against the
unchanged raw original stdout, and source generation then completed. This was
a local preparation failure, not another remote collection or measurement.
No collector, installer, original auditor or workload was executed locally.

The original R34 workflow completed but its C8 performance gate rejected the
candidate. Normal lifecycle, its materializer and capacity execution remain
unrun. This archive repair does not change those outcomes or adopt R34.
