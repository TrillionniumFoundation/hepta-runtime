# D1 ordinary configuration qualification and evidence closure

D1 is diagnostic instrumentation on accepted R24. This evidence commit adopts no runtime optimization and makes no performance improvement claim.

## Actual completed gates

| Gate | Original job | Result |
| --- | --- | --- |
| Feature-enabled original eight-stage qualification | 1a1aff8769c-fc05-6d26 | Passed; 1651 passed, 0 failed, 34 ignored, 1685 selected, 0 retries |
| Exact local CI check/list/nextest run | 1a1b0238605-fc05-6e78 | Passed; 1651 passed, 0 failed, 34 ignored, 1685 selected, 0 retries |
| Ordinary feature-off five-stage supplement | 1a1b04c6cd1-fc05-6f94 | Passed; 1645 passed, 0 failed, 34 ignored, 1679 selected, 0 retries |
| Original ordinary read-only postflight | 1a1b06d14dd-fc05-7074 | Passed; native terminal succeeded/0, complete stdout 296 bytes, stderr 0 |
| Ordinary evidence collector | 1a1b0779748-fc05-70b1 | Passed; native terminal succeeded/0, complete stdout 684 bytes, stderr 0 |

The ordinary stages are clippy, test-build, isolated-tests, audit-isolated-tests and release. All five exited 0. The 222 compiler inputs and the 19 original qualification harnesses remained unchanged. Feature-enabled qualification binaries and ordinary release binaries retain separate identities.

The first ordinary launch failed before any Rust stage because the prerequisite binder did not allow the exact original CI manifest path. Its native originals remain in ordinary-attempt-01-failure. The narrow correction and its provenance are retained; that failure is not rewritten as a successful run. A transport artifact with an extra newline in each of three native copies was rejected before deployment; the corrected transport retains the exact original raw bytes.

## Full ordinary archive

The original collector selected 3362 files and 6761687 bytes, including the complete original compressed stage/test logs. Its returned archive is 1455951 bytes, SHA256 3a99b65020e6823b60b87700d50e430c1def76c15fe387beb4a9032e7294fffe. Manifest SHA256 is 382f861e031913fb7e844c9a3bae1103a522dbd1987cee26fec3ad69e610cdd2.

The identical collector verified the transferred archive locally with files_extracted=0 and verified=true. This checks archive contents without executing any archived program or rerunning an original test/auditor.

Raw native terminal and read envelopes are stored byte for byte. Their request fingerprints and timestamp/version strings have not been reconstructed by JSON parsing and serialization.

## Ordinary release identities

- hepta-runtime: 3250f60d22f5b1aa02e56f0cf082ddc550ef9c3e4cf654a90bd9637cfe3679c4
- hepta-runtime-jobctl: 61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62
- native_process_driver: 1a9cae1a4b1565937b8e77ceabfe486b12857e1439213b7a8be123428d906727

## Next measurement

The C1 diagnostic campaign is separately sealed against the actual successful ordinary postflight. It retains one feature-enabled ELF for OFF/ON/ON/OFF, six hosts, the original 90-second quiet period, monitor, holder, native auditor and owner closure. At this evidence checkpoint the formal campaign has not started and no C1 result is claimed.

Accepted optimization remains R24. R35 remains rejected because its mandatory normal lifecycle concurrent-cancel throughput ratio was 0.9293926467609281, below the unchanged 0.95 floor. Aggregate gains do not override that rejection.
