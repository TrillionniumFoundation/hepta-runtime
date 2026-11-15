# Lifecycle archive relocation: reviewable candidate

This directory is an isolated scratch review. The running source checkout was
not changed. The patch applies to the existing lifecycle consumer and its
existing test file only; `git apply --check` against the frozen checkout passed.

## What changes

`recorded_output_root(fixtures)` derives the original output directory from the
authenticated `prime` fixture's absolute `workspace/prime.elf` path. It uses
`PurePosixPath` and lexical canonical-path checks only. It does not resolve,
stat, open or otherwise grant authority to the recorded location.

Only the execution metadata expectations change: native launch config argv,
both producers' launch cwd, the runtime configuration's recorded paths, and
each fixture's recorded path. Those fields must still agree with one original
output directory. All artifact references remain confined to the current
archive root. The current repository/source snapshot, executable identities,
original raw wire, FD links, process identities and normal-close checks remain
unchanged. No original receipt is rewritten and no qualification gate is added.

Existing source pins are deliberately retained. An old producer receipt is not
automatically upgraded to this changed consumer/source combination. A new
candidate must create its own receipt, then demonstrate byte-preserving
relocation of that receipt and its selected source checkout.

## Verification

From `candidate/`:

```sh
python3 -B tests/rea_lifecycle_qualification_tests.py ArchiveRelocationTests -v
```

All **9 new tests passed** in 0.541 seconds. These use a complete six-session
synthetic **OPEN** receipt: the active phases are explicitly unobserved. They
do not manufacture lifecycle or provider success. The positive migration test
first validates the original, copies its complete bytes, deletes the original
directory, then validates the copy while forbidding old-path `Path.open`,
`Path.stat` and `Path.resolve`. Both assessment objects and every artifact byte
remain identical.

Negative controls re-pin altered config, fixture, launch and trace artifacts;
they must still reject rebasing execution to the archive or contradicting the
original wire. Absolute/traversal/symlink artifact references, source changes,
binary substitution and forced cleanup remain refused or FAILED. The separate
reviewer confirmed that all four current-root execution-metadata dependencies
were covered and no other ownership or provenance check was loosened.

The current lifecycle read helpers retain their existing containment contract;
this patch does not claim new resistance to a malicious operator replacing all
records or to filesystem races outside that existing contract.

## Exact patch

- `lifecycle-archive-relocation.patch`: 17,439 bytes; SHA-256
  `37620d8240e2a2c45f2fa08eb9493c17e0a1dfe853c7db063d01621103c550bd`.
- Candidate `scripts/rea_lifecycle_evidence.py`: SHA-256
  `2826be2c3e9e009eb0a1ac7e2942ee8bae5e97f3a6ed2ed9829c2e4b94a25849`.
- Candidate `tests/rea_lifecycle_qualification_tests.py`: SHA-256
  `e4d4dbf1913e3e3b27135f03e2491043450aa0b7156a54328dd79895203c436e`.

Application belongs after preservation and termination of the prior matrix.
The new actual lifecycle run should be checked once at its original output
directory and again from a separate relocated archive, with the same unchanged
receipt SHA-256. Synthetic refusal tests alone do not establish that real run.

## Publication boundaries from the read-only audit

The reviewed source commit `31c577bb5f083ffb6aac2a02062556975240a8ae` contains
exactly the 32 files in the final r3 manifest, with identical bytes. Its parent
is `b3bac9e47fd09ee2c6bb0d62802bd55b7662f366`. That candidate's matrix subsequently
reported two actual failures; preserve it as that candidate's result. The
corrected source and this patch require their own commit and complete matrix.

1. The ledger contains **34 source-discovered REA interfaces in total**, with
   **two new interfaces** this round. This is neither 34 new interfaces nor
   34 qualified upstream tools. The frozen npm denominator is 229 operations
   in 18 families: 187 absent, 22 partial-operation, 20 related-facility, and
   **0 qualified / 229 OPEN**.
2. A build matrix's `qualified: true` belongs to its build-matrix schema. It
   does not change operation or deployment qualification. Report actual final
   terminal summaries, including skips and stopped/skipped stages; a planned
   test count or partial green progress does not establish a complete run.
3. If the new real family replay passes, say **50 finite comparisons**: 40
   paired public CallToolResults, three contract sets and seven export-byte
   pairs. Native page calls are separate. Eight normal owner closes are
   separately observed. The family assessment remains OPEN/qualified=false;
   complete text, parsed values and exact outer wire bytes remain distinct.
4. Native byte pagination/release is `hepta.evidence-bundle-readback.v1`.
   `inspect_analysis_view` still refuses an ELF-notes parent. Explicit
   export/import does not provide automatic restart persistence, restoration
   of snapshot handles, or qualification of unknown-bearing Evidence types.
5. The family consumer does not merge the separate lifecycle assessment.
   A successful native 30-second worker deadline does not close the original
   Node in-process deadline boundary. Full format/compression coverage, all
   readback capacity/cancellation profiles, concurrent faults and other
   platforms remain separate requirements.
6. Ghidra's 15-row, six-field comparison is a finite fixture projection, not
   complete upstream Evidence/decompiler/reference/error parity. Its original
   full 146-option snapshot was not captured directly; the default-profile
   comparison is an explicit inference. NoReturnFix's zero changes apply only
   to that fixture. The historical 3,002-file Ghidra-only API identity does not
   authenticate the final 3,139-file Ghidra+GPL scope.
7. Static providers still require a Linux controller and executing Linux
   host; the new default profile fixes x86:LE:64:default/gcc and the selected
   Linux x86_64 helper. Rust implementation of the ELF/Evidence path does not
   qualify macOS/Windows/Android providers or remove external Ghidra/JDK and
   remaining general Python helpers. Release cost, deployment, multi-host
   concurrency, upgrades and rollback remain P5 gates.

## Evidence commit and binary provenance

`Selection` in `scripts/rea_full_qualification.py` excludes `.git` and generated
`docs/qualification/**`; it explicitly includes four frozen reference files,
including the capability map. Build and family consumers compare selected
source inventories, original stage artifacts and the exact native executable
digest. They do not obtain the current Git HEAD and do not rewrite binary
provenance from a later documentation commit.

Therefore a later commit adding only new qualification documents/archives can
preserve the original source/binary binding. Keep separate fields for the
actual build-source commit, selected source-tree SHA-256, binary SHA-256,
original build-summary SHA-256, and the later evidence/publication commit.
Do not rewrite original summaries to the publication HEAD. The ledger's
`runtime.baseline_commit` is historical mapping metadata, not the new binary's
source commit. The 32-file delta manifest is not a replacement for the full
execution-input snapshot and inotify record.

Changing scripts, tests, runtime files, any of the four selected reference
files, or their modes invalidates that execution-source binding. Editing
historical evidence files already named in map `source_paths` can also change
the ledger's own source manifest; merely adding new evidence directories does
not. The lifecycle field `binary_source_commit_declared` remains a declaration
whose compilation provenance requires the enclosing build consumer.

The ledger re-derivation's `raw_reference_authenticity: NOT_REVERIFIED` means
the offline mapping pass did not reacquire/re-authenticate original reference
artifacts. A later actual npm family run's own pinned package validation is a
separate observation and should be reported separately.
