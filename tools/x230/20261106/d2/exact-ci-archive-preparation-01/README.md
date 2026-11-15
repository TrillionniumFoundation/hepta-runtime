# D2 native exact-CI evidence archive — unsealed preparation

This package preserves the original D2 native CI attempt. It does not run CI,
Cargo, a test, the nextest auditor, a prerequisite binder, or a workload. The
collector remains `ACTUAL = None` until the original terminal, complete native
read pages and original plan/report/audit have arrived. There is no successful
CI count or future result filled in from the already passed qualification.

## Fixed scope

The 19 fixed payloads are the 12 actual CI deployment members and seven original
D2 qualification records. These bind the current 59,048-byte canonical
`full-prerequisites-01/d2_prerequisites.py`, Q-only foundation, six CI tools,
canonical published workflow, actual CI sealing metadata, and qualified 222-file
map. No earlier owner archive is recursively copied. Complete compiler sources,
ELF bodies, target caches and credentials are outside this archive's scope.

The collector additionally retains the original CI plan, terminal and every
contiguous original native read page, installation claim/receipt, and every
allowed file below `rust-ci-01/`. All twelve stage stdout/stderr streams and
nextest's original inventory/output are retained. Successful stage stream bytes
must match their original report identities. A failed original attempt keeps its
actual stage fields and has `counts = null`; qualification success is never
substituted for CI success.

The report summary checks the existing six commands, original environment,
complete original cleanup flags, plan/source/Q identities, original unfiltered
case inventory, and existing nextest-audit raw hash/counts. It interprets already
recorded facts; it does not rerun the auditor, inspect live source/ELF bodies, or
claim hosted Actions, benchmark success, or candidate adoption.

## Original I/O and preservation boundaries

`reference/archive_d1_qualification.py` is the exact 63,482-byte D1 Q archive03
source (Git `0ecf10a045896b0e14822f2816c68c60434f7713`). That original accepts
`kind=qualification` only; it has no generic CI mode. This preparation reuses its
stable no-follow readers, private-key scanner, bounded tar/gzip, exclusive writes
and zero-extract verifier. Only the fixed member selection and pure receipt
summary are CI-specific. The common create/verify paths change namespace, kind
and output basename, not their I/O rules. Native pagination uses the original
canonical binder function, with a maximum of 16 original pages and 16 KiB per
stream per page. Original native JSON bytes are never reconstructed or given an
extra newline.

Limits remain 32 MiB selected bytes, 8 MiB per member, 2 MiB manifest and 8,192
members; the tar expansion limit is unchanged. The three output files together
must fit 32 MiB. No temporary extracted directory is created. An interruption
retains any partial output; the collector neither removes it nor retries under
the same names. The collector source itself stays outside the selected payloads
and is separately preserved by Git plus the archive's `tool_sha256`, because its
unchanged credential-scanner literals would trigger its own scanner if archived.

## Once actual originals exist

Complete a new copy of `actual-seal-request.unsealed.json`: give the exact local
path, bytes and SHA256 for each actual core original; keep a genuinely missing
record `null` only on the failed-attempt path. Set the original job ID and exact
read-page names. A single `rust-ci-native-read-01.json` or contiguous
`rust-ci-native-read-01-000.json`, `-001.json`, ... are accepted. No fabricated
combined native-read JSON is accepted.

Run only the local sealer into a fresh directory:

```text
python3 -B seal_archive.py --input ACTUAL_REQUEST.json --output NEW_SEALED_DIRECTORY
```

This produces the sealed collector, actual pins and seal receipt. It performs
pure original-record checks; the subsequent collector additionally checks all
retained stage raw streams. The sealer creates no target outputs and invokes no
collector function. Root alone installs the sealed collector, for example at
`/home/qian/hepta-runtime-validation-cost-20261106-d2/archive-ci-tools-01/archive_d2_ci.py`,
then performs the single read-only archive action:

```text
/usr/bin/python3 -B -u /home/qian/hepta-runtime-validation-cost-20261106-d2/archive-ci-tools-01/archive_d2_ci.py --kind ci
```

The create-only results are `rust-ci-evidence-01.tar.gz`,
`rust-ci-evidence-01.manifest.json` and `rust-ci-evidence-01.compact.json` under
the D2 root. Retain that action's original native terminal/read pages separately.
After the original archive is transferred and its whole SHA verified, use the
same exact sealed collector locally:

```text
python3 -B archive_d2_ci.py --verify /absolute/path/rust-ci-evidence-01.tar.gz --expected-sha256 ACTUAL_ARCHIVE_SHA
```

Verification does not extract files or execute archived Python. Its `verified`
result means the complete retained byte set and pure recorded-fact summary agree;
it is not a new live machine, compiler or performance observation.

## Preparation status

Only source generation, AST parsing, byte/hash comparison and Git preservation
have occurred. The original CI job is operated by root. This unsealed package
does not assert its terminal state, pass count, archive existence or outcome.
