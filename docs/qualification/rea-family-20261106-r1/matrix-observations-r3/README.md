# Independent R5 build and matrix observations

The completed nine-stage matrix and its independent original-receipt consumer passed for
source commit `fe3223cabbd2a8f1aa75a4ab57507bdb72291242`. The 1,429 selected execution inputs
have tree SHA256 `1a83f83cf62bf3d96e50c944722977b6971ffe686aecd131cab5e728dd802424`.
The independent consumer bound every selected Git blob and executable bit to that commit;
current publication HEAD is recorded separately.

| Test configuration | Actual PASS rows | Binaries reported | Reported skipped | Reported slow |
| --- | ---: | ---: | ---: | ---: |
| All features | 2,327 | 18 | 40 | 0 |
| No default features | 2,298 | 17 | 28 | 0 |

Each row is independently recovered from the complete nextest logs, including unique test
identities and sequential counters. These are two feature-specific executions, not 4,625
distinct tests. Skipped counts are reported totals: individual skipped identities and
doctests are not claimed. Both Clippy configurations and formatting passed. The other
stages retain actual Cargo/Rust/nextest version output and the explicit final native build.

The final binary was 51,146,872 bytes with SHA256
`260205be5fd4cdf363b8f426002c057d1d939ce299843f979770a585bb72faf6`.
Cargo identified its real binary target, `default` and `remote-fs` features, `fresh: false`,
optimization level 1, zero debuginfo and a non-test profile. Development/test debuginfo were
set to zero and incremental compilation was disabled. The independent audit hashed the
binary before and after consumption and never executed it. Binary contents are excluded
from Git and this package; the observed original path and full file identity are retained.

Matrix job `1a1b271e886-fc05-7e0b` and independent-consumer job
`1a1b29ce966-fc05-7eee` both exited 0 with complete durable stdout and empty stderr.
Their exact worker requests, inline commands, launcher, raw terminal records and output
bytes are retained. The matrix's nine stage exits and the independent audit's actual
result are separate evidence. The original source-freeze receipt, immutable launcher,
launch/outcome metadata and raw resource query are included without rewriting them.

Resource observations belong to the complete user-systemd developer-build unit, including
launcher overhead. Its 400% CPU-time quota, 12 GiB memory limit and zero-swap limit matched
the requested profile. Observed MemoryPeak was 6,863,306,752 bytes and CPUUsageNSec was
2,791,605,110,000. I/O accounting was unavailable. These are not per-stage measurements,
release costs, storage-budget measurements or deployment qualification.

`assessment.json` is the exact 19,952-byte independent result, SHA256
`48b7045b56cbbdb91ac67fa5ab67245279d466be4fd53a7ffe9749b799632fdd`.
`original-build-evidence.tar.gz` holds exactly the 22 original summary/source/monitor/log
files. `matrix-observations.tar.gz` additionally preserves the independent snapshot/Git/
binary observations, actual original replay outputs, complete per-test rows, scripts,
peer review, preparation data-check source and the terminal job metadata. No build or test
was rerun for archiving. The source/monitor records bind the completed build; toolchain and
dependency cache remain trusted external inputs rather than included or hermetically
reproduced artifacts.

Every archive member was bounded, validated against unsafe names/duplicates/links/special
files, physically extracted into a new private root and read back. The frozen build
consumer successfully replayed the exact 22-file bundle from that relocated root;
`archive-replay.json` records that actual result. This replay checks retained observations
and does not claim to freshly observe a binary that is absent from the archive. All
original file hashes were rechecked after sealing and no original receipt was modified.

The scripts in `tools/` include the frozen independent consumer, its seven pure-log data
checks, both pinned repository modules and the archive helper. Full independent source
and binary re-observation requires the matching source checkout and separately retained
binary. A receipt-only replay uses the preserved `consumer-run/bundle.json`,
`independent-source-before.json` and `native-file-observation.json` with
`rea_build_evidence.validate_bundle` rooted at the extracted `consumer-run` directory.
Recorded original absolute execution paths remain metadata; artifact reads use that root.

The result verifies this local build/source/binary binding. Operation qualification stays
`qualified: false` and 0/229. ELF/Evidence behavior, complete Ghidra Evidence equality,
cross-platform support, release deployment and remaining P0–P5 work require their own
separate observations. Later documentation/evidence commits do not change the recorded
binary source commit.
