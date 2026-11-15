# Final release r2: real Chrome and Ghidra under the original outer resource profiles

The new release `aa580409a73bc2e0927ead93d32634239051a39fc951c3c2a92d5a1dece8347a` (18,437,864 bytes) passed the
original finite Chrome and Ghidra gates in fresh **r3** runs. All four original
harness files and their assertions and inner budgets remained byte-for-byte
unchanged. Chrome completed successfully before Ghidra was launched.

The release build receipt has SHA-256 `0541d43b62f631b3ebcda4895bafc5cdc087ac94460780191c0e61a4f043292d`. It binds source
commit `ed74d9dbf04b97fad38112c2ac08127bf99b3590`, equal before/after source tree digest
`4021ee22efdf2eac830e08afc45eddf37b264e7fd31a222c329b4950ef2d94b6`, and zero source-monitor events, errors, or
truncation. The wrappers checked the original release, the independent frozen
copy, build receipt, selected source/test/configuration files, and harness pins
before and after each run.

## Results on the exact original outer request profiles

| Gate | Observed result | Harness duration |
| --- | --- | --- |
| Real native Chrome capture and saved HAR operations | 11 checks passed | 30.903 s |
| Retained Python reference differential | 10 selected pairs and the independent body/metadata oracle passed | 0.556 s |
| Fixed native browser deadline | 6 checks passed; original 1 s manifest and 100 s child-job ceiling | 6.643 s |
| Real Ghidra analysis and native decompilation | 8 checks passed | 229.411 s |

The Chrome outer job `1a1a743d8ad-fc05-2ac5` took
38.541 s. The Ghidra outer job
`1a1a746ae3e-fc05-2acf` took 229.701 s.
Both authoritative durable status observations report success, exit 0, complete
durable output, confirmed terminal publication, and no timeout, cancellation or
automatic retry. The observations are serialized without dropping fields in
the two durable-terminal JSON files.

| Outer supervisor request | CPU quota | Memory maximum | nice | Timeout |
| --- | --- | --- | --- | --- |
| Chrome: original and current r3 | 400% | 4,294,967,296 bytes (4 GiB) | 10 | 1200 s |
| Ghidra: original and current r3 | 400% | 8,589,934,592 bytes (8 GiB) | 10 | 1200 s |

The actual durable request files are retained under `outer-requests/`.
The comparison checks every field except the explicitly listed job identities,
wrapper/output locations, and generated request/launch identifiers. Environment,
execution mode, executable, platform, network/fallback settings and all resource
fields are equal to the original requests. Both new launches used the systemd
backend. These are **outer supervisor request limits**; this record does not
claim that separately supervised inner engine units share the outer cgroup.

## Preserved r2 attempts and the required correction

The earlier runs on this same new binary, `1a1a73885a7-fc05-2a9c`
and `1a1a738d222-fc05-2a9e`, passed their original core
harness assertions but omitted the original outer CPU and memory limits and
used nice 0. Their suites also briefly overlapped. They therefore do **not**
qualify execution under the original outer resource profiles and sequencing.

Their raw wrapper reports, serialized terminal observations, actual durable
requests, and explicit scope correction remain in this archive. The raw
`qualified: true` fields are preserved as the original harness results;
`prior-r2/scope.json` records the missing outer-profile qualification.
No r2 output was overwritten or converted into a new-profile PASS. Fresh r3
jobs performed the necessary rerun with exact original requests, and the
original 1200 s outer and all inner timeouts were retained. Each job's
`retry_count: 0` describes that wrapper's automatic retry count; it does
not conceal this separately recorded manual requalification.

## Chrome evidence and limits

The unchanged native gate exercised durable jobs and MCP routes, changed-input
refusal, complete/empty/base64/missing and repeated-request observations,
receipt durability, original-key reuse, cold-controller recovery, saved HAR
inspection/comparison/replay, and cancellation with private browser/profile
cleanup. The replay observations are limited to the two owned sentinel origins.

The original Python reference was read without mutation or a new reference run;
its qualification SHA-256 remains
`797f986ef548582956a91dac5bac364f7f328b40003b00128b553120820148c7`.
The compact differential retains all 10 case keys, body/metadata equality
outcomes, independent manual-oracle outcomes, exact input/report identities,
and the original false scope flags. The full new report remains outside the
checkout, bound by SHA-256 in `browser-differential-projection.json`.

The deadline fixture retained 32 delayed resources, 2 s authored delay per
resource, a 1 s native capture deadline, and a 100 s child-job ceiling. Its
observed request-to-terminal interval was 2.858 s.
The expected inner job failed with exit 1 under the native capture deadline;
the outer timeout did not fire. No successful HAR/receipt was published and
the owned browser/profile was gone. This negative-case outcome is the expected
success condition for the deadline gate, not a successful capture.

This scope is fixed owned HTTP-resource observation. It does not qualify
application script execution, input-page DOM inspection, general browser-session
replay, process-level network isolation, changed-session descendants, full HAR
equivalence, raw HTTP wire equivalence or application-behavior equivalence.

## Ghidra evidence and limits

The test used the existing pinned Ghidra 12.2 and JDK 25.0.5 installations,
operator mode, and the explicit localhost SSH flag. The unchanged eight checks
cover owned nonexecuted ELF fixtures, function-entry comparison with GNU nm,
incoming calls compared with GNU objdump, real native decompilation and the
selected C digest, recovery after controller restart, changed/invalid/interior
selectors, and cancellation during live Java plus native-decompiler execution.

The cancellation receipt records the original Java/native process identities,
their disappearance, the unsuccessful cancelled result, and original-key reuse
without engine relaunch. **The unchanged harness removed one private scratch
directory after cancellation.** This does not claim that the runtime itself
cleans every cancelled scratch directory.

The provider executed zero target programs. `isolated_host_qualification`
and `rea_full_parity` remain false. The finite operator gates do not
qualify a separate isolated-host deployment, the complete upstream Ghidra family,
all function-wide xref semantics, or the full REA Evidence/session contract.
The frozen 229-tool full-parity objective remains open.

## Retention and reproduction

The exact command vectors, working directories, release/source bindings,
selected source-file hashes, harness hashes, durations, and individual log
identities are preserved in `browser-wrapper.json` and
`ghidra-wrapper.json`. Raw current qualification/cancellation files and all
six durable request files were copied without byte changes. The differential,
resource comparison, prior-attempt scope, transformation record and manifest
are explicitly derived archival records.

The private r3 wrapper is `/tmp/rea-final-engine-rerun-20261104-r3/run_engine_regressions_r3.py`, SHA-256
`c31635908e7a43562dbebc7563b139eff77a6cadb95c81262e0bca2319ab7e4d`. Its exact bytes are retained as
`engine-wrapper-source.txt`. Relative to the original wrapper, only new
release/build identity constants, binary size and output directories changed;
the r2-to-r3 edit changed one output suffix. The four harness files and all
gate assertions/budgets remained unchanged. The outer request fields were
restored through the process_start calls and independently checked in the
actual durable request files.

All new working directories and outputs are outside the root checkout. Python
uses `-B` and `PYTHONDONTWRITEBYTECODE=1`; no matrix-specific TMPDIR
setting was added. Full new evidence remains under `/home/qian-qi/work/hepta-rea-final-independent-20261104-r2/browser-r3` and
`/home/qian-qi/work/hepta-rea-final-independent-20261104-r2/ghidra-r3`. The retained r2 attempts remain in their own original
directories. The old `0595fbf0…` archive and original wrapper are unchanged,
as recorded by the preserved-archive manifest. No production source, tests,
harnesses, build target, engine installation or runtime configuration changed.
