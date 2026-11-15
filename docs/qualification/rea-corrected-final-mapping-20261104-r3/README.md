# Corrected final REA mapping and origin archive — 2026-11-04

The corrected mapping run authenticated the pinned reference inputs and passed
the repository mapping check. **Full upstream parity remains OPEN: 229 published
operations, zero qualified operations.** The strict parity command returned
the expected exit code 3; that is an explicit refusal to certify parity.

This directory retains the original failed cache-path attempt as well as the
corrected attempt. The archive directory suffix is r3; the actual validation
attempts below are r3 and r4. No validation command or runtime test was executed
by this archival work.

## Observed results

| Original attempt | Cached check | Offline mapping | Strict parity | Outer durable job |
| --- | ---: | ---: | ---: | --- |
| r3, wrong cache path | 2 | 0 | 3 | 1a1a76616bc-fc05-2b4d: exit 1 |
| r4, correct existing cache | 0 | 0 | 3 | 1a1a76ade8c-fc05-2b5d: exit 0 |

Both original jobs have complete, durable output and terminal records with
`timed_out=false` and `cancelled=false`. The r3 failure is real: its cached
command selected
`/home/qian-qi/work/hepta-rea-reference-cache-20261104-r1`, and the original
stderr reports a missing
`oracle/REA_6_8_0_ELF_NOTES_EVIDENCE.json` under that selected path. It is not
recorded as a successful check or as a remote timeout. A transport-side read
wait ending does not change the original job's terminal result.

The root owner ran r4 with the already verified cache
`/home/qian-qi/rea-ledger-inputs-20261104-r1`. Its three inner command arguments
and expected statuses are unchanged except for that cache argument. Output
paths and durable job identities are separate; no r3 output was overwritten.
The cached r4 stdout says `inventory_check: PASS` and
`raw_reference_authenticity: VERIFIED_AGAINST_PINS`. Offline and strict
stdout say `mapping_check: PASS` and
`raw_reference_authenticity: NOT_REVERIFIED`.

Original result files:

- [Failed r3 summary](mapping/r3-cache-path-failure/summary.json),
  [cached diagnostic](mapping/r3-cache-path-failure/cached.stderr.log),
  [request](mapping/r3-cache-path-failure/outer-job/request.json) and
  [terminal](mapping/r3-cache-path-failure/outer-job/exit.json).
- [Corrected r4 summary](mapping/r4-corrected-cache/summary.json),
  [cached result](mapping/r4-corrected-cache/cached.stdout.log),
  [offline result](mapping/r4-corrected-cache/offline.stdout.log),
  [strict result](mapping/r4-corrected-cache/strict.stdout.log),
  [request](mapping/r4-corrected-cache/outer-job/request.json) and
  [terminal](mapping/r4-corrected-cache/outer-job/exit.json).

The r3 summary SHA-256 is
`2bba473d61a0b7c8d040fabeb6cd30f470204b36e906d7cbd3d2161e3530c13d`.
The r4 summary SHA-256 is
`442c3df0d8efc83ba576384a533cb90175d28dc50160c4372f0d94f40af19b51`.

## Identities and unchanged inputs

Both validation summaries sampled documentation HEAD
`2623fad7a42e66ead9b4bc254a99d06a900e331b`. This independent documentation
worktree starts at that same commit. The production/test/script freeze remains
`ed74d9dbf04b97fad38112c2ac08127bf99b3590`; its release is
`aa580409a73bc2e0927ead93d32634239051a39fc951c3c2a92d5a1dece8347a`,
18,437,864 bytes. Those release facts are context for the adjacent release
archives, not a claim that these mapping commands executed the runtime binary.

The original r3 and r4 before/after receipts and this archive's copy checks
agree on these complete file contents:

| Repository path | SHA-256 |
| --- | --- |
| `docs/rea-native/compatibility/REA_6_8_0_CAPABILITY_MAP.json` | `99e07b5ab23877f8b2665de27bbdd83c5e9fe813e9e303be93e8522813de15d3` |
| `docs/rea-native/compatibility/REA_6_8_0_LEDGER.json` | `a571d19af36edea73bd0585291eee85649dc4728741cbc7fd67f8ac6cba2b9f9` |
| `scripts/rea_compatibility_ledger.py` | `4edb317e16166b569469323fb2963197a010e59902063640964db41eae7dce4e` |

The retained historical sampling-baseline commit in mapping metadata is not a
requirement that current Git HEAD equal that old commit.

## Final read-only scope audit

Original job `1a1a7648dcf-fc05-2b46` read the map, ledger and relevant
documentation at the sampled HEAD. Its [full output](audits/final-mapping/stdout.log),
[request](audits/final-mapping/request.json) and
[terminal](audits/final-mapping/exit.json) are preserved unchanged.

The exact 26 native MCP handler names and 18 partial upstream operation names
are retained in that original output and projected into
[AUDIT_SUMMARY.json](AUDIT_SUMMARY.json). The ledger counts are 18 partial
operations, 23 related facilities and 188 absent operations, totaling 229.
Native handler counts and auxiliary CLI/worker capabilities are separate
inventories; neither measures completed upstream contracts.

The dedicated upstream `inspect_apk_signature` remains partial. General
`inspect_signature` remains absent, and `inspect_android_package` remains a
separate incomplete operation. Frozen static APK observations, original input
and result contracts, Evidence, retained views and typed outcomes remain
required; Android installability/trust or complete v4 platform verification
are not added as mandatory migration gates.

APK and Source Map lifecycle statements cover their current cooperative MCP
path and qualified worker cases. They do not assert safety for arbitrary
future cancellation/drop during a blocked filesystem read. Selected Ghidra
and Chrome observations retain their actual external engine and launcher/owner
boundaries. JEB was not found in the bounded discovery scope; its license
state is NOT_PROBED, not a proven missing license.

No row is promoted to qualified by this archive. The cached and offline
checks validate inventory and mapping consistency within their documented
scope; they do not execute the full 229 operation contracts.

## Frozen package origin and license

Original job `1a1a7661fb9-fc05-2b4e` inspected existing fixed inputs and the
installed reference package. Its [full output](audits/origin-license/stdout.log),
[request](audits/origin-license/request.json) and
[terminal](audits/origin-license/exit.json) are preserved unchanged.

The actual [package.json bytes](origin/npm-package.json) report
`rea-agents` version `6.8.0`,
`repository.url=git+https://github.com/morluto/rea.git`,
`homepage=https://github.com/morluto/rea#readme`, and `license=MIT`.
The resulting repository URL is [morluto/rea](https://github.com/morluto/rea);
the selected source commit is
[93b8b82db70279e40f484114cff9dc1958dc14ee](https://github.com/morluto/rea/tree/93b8b82db70279e40f484114cff9dc1958dc14ee).
This origin is taken from observed package metadata, not inferred from the
project name.

The [actual npm LICENSE bytes](origin/npm-LICENSE) contain the MIT License
and `Copyright (c) 2026 morluto`, including the copyright/permission-notice
retention condition. Original location:
`/home/qian-qi/work/hepta-rea-reference-20261103/install/node_modules/rea-agents/LICENSE`.
Its size is 1,064 bytes and its SHA-256 is
`798f9e4d18e49b30bf2f12696c8ced73dc4e1413da375a333d01281543a1ea8b`.
The 27,209-byte package.json SHA-256 is
`b0fc212f6bea9b4ee6e2b3ab0b52dd95402c229da3b8652127e5f131c3445b39`.

This audit read the npm package's license. It did not fetch or independently
reread a Git LICENSE blob, and makes no blanket license claim about external
engines or their dependencies.

## Preservation and review

[ORIGINAL_BYTES.json](ORIGINAL_BYTES.json) maps each copied original to its
source path, exact byte length and SHA-256. Empty stdout/stderr files are
retained. Request, terminal, output and selected publication records keep their
original bytes. The additional process-status SDK files are lossless original
SDK payloads retrieved through the closed background read API; retrieving
them did not replay either validation job.

[MANIFEST.json](MANIFEST.json) binds every archived file except the manifest
itself. [AUDIT_SUMMARY.json](AUDIT_SUMMARY.json) is an explicitly derived
projection, not a replacement for the original receipts. All originals were
checked against their observed hashes when copied and against the archive
manifest before the documentation commit. No source, test, script, resource
budget, production deadline, ledger qualification status or original evidence
was changed.
