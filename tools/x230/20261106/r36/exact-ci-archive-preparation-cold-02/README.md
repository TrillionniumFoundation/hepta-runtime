# R36 validation-scratch cold02 exact-CI evidence archive

This is an unsealed, data-only derivation of the already reviewed D2 CI collector
and sealer. The current original CI job is `1a1b1fadfab-fc05-7bda`. Its outcome,
counts, report, terminal and read-page identities remain unknown here. No future
success is inherited from the actual completed qualification.

The nineteen fixed members are the eleven installed CI payloads, the separately
installed `tools-01/r36_campaign.py`, and the original seven Q bodies. The
qualification binder remains the original six-key R35 protocol. The pure archive
summary checks those recorded identities and the actual 220-file map; it never
imports the parent, executes a binder, or repeats any qualification or auditor.
The full CI directory preserves original inventory/output and all six stages'
stdout/stderr. Successful stage bytes must equal the original report hashes.
Failed CI retains its actual fields and has counts null.

The source derives from Git `dab25a5a03db6d1b035aa1722f425af3738e795a`
and sealer `2ca032c1fa01a4396b7d835b349d1c6de3e2a581`. The original
no-follow readers, private-key scanner, exclusive writes, bounded tar/gzip and
zero-extract verifier are unchanged. Limits remain 32 MiB total/combined output,
8 MiB per file, 2 MiB manifest and 8,192 members. Target caches, test/release ELF
bodies, profiles and credentials remain excluded. Collector source remains a
separate Git object, because its unchanged scanner literals are not archive
members. No earlier owner archive is copied recursively.

## Actual sealing

Fill a new request using the exact original bytes and their local paths. Preserve
each original native read page; do not re-encode raw JSON or add trailing bytes.
Both the singleton `rust-ci-native-read-01.json` and an original contiguous
`rust-ci-native-read-01-000.json`, `-001.json`, ... list are supported. The
installation claim and receipt are mandatory originals. Future absent records
are allowed only for an actually failed attempt.

```text
python3 -B seal_archive.py --input ACTUAL_REQUEST.json --output NEW_SEALED_DIRECTORY
```

This invokes only the data sealer, which writes the sealed collector, actual pins
and a seal receipt into a new directory. It does not import or execute the
collector, binder, nextest auditor, Cargo, tests or any host command.

Root alone stages the exact sealed collector at
`/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/archive-ci-tools-01/archive_r36_ci.py` and creates the archive once:

```text
/usr/bin/python3 -B -u /home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/archive-ci-tools-01/archive_r36_ci.py --kind ci
```

Outputs are `rust-ci-evidence-01.tar.gz`, `rust-ci-evidence-01.manifest.json`
and `rust-ci-evidence-01.compact.json` under that ROOT. Preserve this metadata
job's original native terminal/read separately. Keep partial outputs on errors;
there is no overwrite, automatic retry or target replay.

After complete transfer and whole-file SHA verification, use the same sealed
collector locally:

```text
python3 -B archive_r36_ci.py --verify EXACT_ARCHIVE.tar.gz --expected-sha256 ACTUAL_SHA256
```

This verifies retained bytes and recorded-fact consistency with zero extraction.
It does not claim a new live source/ELF check, hosted Actions success, performance
acceptance or adoption. Actual CI tests and gates are unchanged.
