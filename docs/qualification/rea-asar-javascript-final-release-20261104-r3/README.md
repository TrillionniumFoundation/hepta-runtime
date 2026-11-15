# ASAR and JavaScript gates on the repaired unified release

The original seven external ASAR/JavaScript commands passed against the new frozen release on 2026-11-04. This is a fresh qualification cohort. Earlier `0595fbf0…` results and the r1 full-matrix failures remain unchanged in their respective archives.

## Exact release and input binding

- Runtime SHA256: `aa580409a73bc2e0927ead93d32634239051a39fc951c3c2a92d5a1dece8347a`; 18,437,864 bytes.
- Source freeze: `ed74d9dbf04b97fad38112c2ac08127bf99b3590`.
- Release report schema: `hepta.rea.unified-release-build.v1`.
- Original release report SHA256: `0541d43b62f631b3ebcda4895bafc5cdc087ac94460780191c0e61a4f043292d`.
- Current full build selection: 641 files, inventory tree SHA256 `4021ee22efdf2eac830e08afc45eddf37b264e7fd31a222c329b4950ef2d94b6`, equal to both release-build snapshots.
- Legacy source selection: 308 files, SHA256 `c9299373b62b93f9229926aa4c904158cb5562a82392bdcb89ab248c46e466cb`.
- Legacy verification selection: 645 files, SHA256 `455b490f167deaa4e520ab29d9982d36730ca57c3b3542ae615279185b74f216`.

These inventory digests are SHA256 values produced by the recorded inventory algorithms, not Git tree object IDs. The source and verification selections were recomputed from current ROOT; the unchanged verification digest was observed again, not carried forward without checking. The full selection was compared file for file with the new build before/after inventories during preparation and final evidence verification.

All 26 pinned inputs and four runtime copies were checked again after the gates. Both command runners retain identical before/after source and verification inventories. See [final-summary.json](final-summary.json), [final-pins-after.json](final-pins-after.json), [release-envelope-verification.json](release-envelope-verification.json), and [build-binding](build-binding/summary.json).

## Seven commands and unchanged execution profile

| Phase | Original command | Exit | Seconds |
| --- | --- | ---: | ---: |
| legacy | `pins-before` | 0 | 0.327 |
| legacy | `normal-mcp` | 0 | 1.594 |
| legacy | `babel-manual-golden` | 0 | 0.375 |
| legacy | `pins-after` | 0 | 0.293 |
| lifecycle | `asar-external-mcp` | 0 | 11.104 |
| lifecycle | `asar-real-producer-lifecycle` | 0 | 33.394 |
| lifecycle | `javascript-cancellation` | 0 | 0.947 |

The fixed runner remains SHA256 `f7f449dbcbd7705876c7cc953937411ad07d521117285db2159e646a1942dec1`. Both plans were compared structurally against the preceding seven-command cohort after substituting only the evidence directory, runtime SHA/size and recomputed source digest. Gate code, fixture bytes, manual goldens, expected results and cancellation/deadline limits were unchanged. The normal MCP external executables ran three real Rust tests in total: one legacy JavaScript test and two ASAR tests.

The complete outer resource fields were read from the original durable requests and compared with the actual new durable requests:

| Phase | Original job | New job | CPU quota requested | Memory cap requested | Nice | Outer timeout |
| --- | --- | --- | --- | --- | ---: | ---: |
| Legacy | `1a1a6d996fd-fc05-290e` | `1a1a749c6af-fc05-2ad9` | null | null | 0 | 180 s |
| ASAR / cancellation | `1a1a6db6062-fc05-291b` | `1a1a74b1bd3-fc05-2ae2` | null | null | 0 | 300 s |

Here null means the request did not add that limit; it is not a claim about every possible inherited host limit. Original and new requests, exact exit records and matching publication witnesses are retained in [resource-profile](resource-profile/actual-profiles.json). The actual request SHA256 values are `18db14f18279965e714e2459312f94b27ab7e14df782df3d283fd8d2b0c7f593` and `c1d3d1c08700268fa7328c9c1896b7ee187b4b83ef051d61e17525f1c216207e`.

The external tests used their original private workspace profile under `/home/qian-qi/work/hepta-rea-final-asar-js-20261104-r3-evidence`, with its own `tmp` directory. They did not adopt the functional tmpfs profile used for the separate Rust/Python matrices. No Cargo build or use of the root-owned target directory was performed by these seven gates. Gate retry count is zero.

Both official controller terminal SDK payloads report succeeded/exit 0, no timeout/cancellation, confirmed terminal publication, complete durable output and no truncation. Exact original payloads are retained in [provenance](provenance/legacy-terminal.original-sdk.json).

## ASAR result

The actual `@electron/asar` 4.2.0 producer/consumer gate passed all eight checks:

- Complete native inventory matched upstream and independently authored names.
- 24 selected member range comparisons and complete selected-member SHA256 checks matched the independently authored bytes and upstream.
- Explicit ASAR graph acquisition preserved ordinary source identity and observations.
- Malformed, conflicting, unsafe, stale and non-UTF8 inputs were refused as expected.
- Reconnection re-observed the same pinned archive.
- A genuinely stopped owned worker was cancelled, reaped by its live original owner and followed by a successful call on that same owner.
- A separately stopped owned worker reached the production deadline, was reaped and followed by same-owner recovery.
- Fixtures remained unchanged and target code was never executed.

There were 55 ordinary probes, including 23 expected refusals. Cancellation completed in **0.031425591 seconds** inside the fixed five-second observation window. The independently exercised production deadline was observed **20.035755374 seconds after confirmed worker stop**, with the production timeout unchanged at 20 seconds. No manual worker kill fallback was used.

See [ASAR qualification](asar/qualification.json) and the preserved producer reference/header, ordinary probe, lifecycle and MCP artifacts. Header digest scope remains the complete Pickle header. Member integrity is archive-provided consistency evidence, not publisher authentication; this gate does not claim complete-archive authenticity or the full upstream archive API.

## Existing JavaScript result

The independent Babel/manual-golden comparison matched exactly:

| Observation | Expected | Actual |
| --- | ---: | ---: |
| Imports | 17 | 17 |
| Exports | 16 | 16 |
| Electron calls | 12 | 12 |
| IPC edges | 4 | 4 |

Both Babel and Rust passed the unchanged independently authored export-count and corrected-observation goldens. The manual golden remains SHA256 `d6ec76c812c7cd91305bb9815cf9ca79e8859f51df14cd506e152ced1afcd015`.

The separate JavaScript lifecycle gate passed all four checks. Its actually stopped owned worker was cancelled and reaped in **0.031014685 seconds**, within the fixed five-second window; the same owner successfully handled the next call. No manual worker kill was used. This JavaScript harness does **not** independently exercise the production deadline; configured deadline metadata must not be interpreted as such a measurement. See [its qualification](js-cancellation/qualification.json).

## Two setup failures preserved separately

Two earlier setup attempts did not execute a test:

1. Preparation job `1a1a73a0ec2-fc05-2aa4` stopped with `KeyError: 'final_binary'` before creating the evidence directory. Its adapter had initially assumed the full-matrix report shape instead of the new standalone release-build schema.
2. Launcher `1a1a73e97be-fc05-2aad` then stopped while reading the not-yet-created fixed runner. Its outer timeout request was 300 seconds, which differs from the original 180-second legacy profile; no harness or test started under that request.

The corrected preparation bound the externally pinned build report, independently checked candidate bytes and compared current/build source inventories. The real legacy run additionally checked the exact new schema and `binary` fields before execution. It used the original 180-second profile, and the real lifecycle run used the original 300-second profile. The setup errors, original read payloads and durable request/exit/log evidence are retained in [setup-failures](setup-failures/index.json). They are not omitted, reclassified as successful tests, or counted as gate retries.

## Scope and preservation

This archive qualifies bounded ASAR acquisition and the existing JavaScript regressions on this exact release. It does not establish complete REA parity, full archive extraction, the full Rust/Python matrix, external engines, or a fix for the historical canary timeout. The [r1 failures](../rea-continuation-matrix-failures-20261104-r1/README.md) remain intact.

Original JSON artifacts are copied byte for byte. Other selected raw artifacts are lossless JSON wrappers with original byte counts and SHA256 values. Generated bulky fixture payloads remain in the external evidence workspace; their hashes and fixed generators are retained in [omitted-artifacts.json](omitted-artifacts.json). Runtime binaries, runtime configuration/token files and temporary owner databases are not included. The controlled non-secret durable job requests are retained to establish the requested resource profile.

[manifest.json](manifest.json) maps original evidence to archived bytes and hashes. Every included raw artifact was verified against its recorded hash; every lossless wrapper was decoded and checked; all manifest entries were re-read before the docs-only commit.
