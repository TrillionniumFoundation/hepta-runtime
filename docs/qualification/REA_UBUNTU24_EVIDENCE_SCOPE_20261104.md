# Ubuntu 24 qualification evidence: scope and provenance, 2026-11-04

This index explains the two frozen Ubuntu 24 evidence imports and distinguishes original on-disk job records from summaries derived from tool responses. It is an outer explanatory document. It does not replace, edit or reserialize any imported payload or transfer manifest, and writing it did not run a build, test or engine.

## Two complementary archives

| Imported directory | Purpose and result | Original manifest |
| --- | --- | --- |
| [Environment, dependency preparation and r2 failure](rea-next-ubuntu24-environment-r2-20261104-r1/) | Fixed Ubuntu 24 image preparation, locked public registry dependency preparation, the original dependency-audit failure and correction, and the first container matrix. The matrix remains failed: 1,882 passed, four failed, 39 existing skips; test command exit 100; no release was qualified. | [r2 transfer manifest](rea-next-ubuntu24-environment-r2-20261104-r1/transfer-manifest.json) |
| [Complete r3 matrix and original job records](rea-next-ubuntu24-matrix-r3-20261104-r1/) | The separately authorized corrected-environment run completed all 35 commands with their original expected exits. This archive also supplies the original on-disk job records for environment preparation, dependencies and the failed r2 run. | [r3 transfer manifest](rea-next-ubuntu24-matrix-r3-20261104-r1/transfer-manifest.json) |

The original transfer identities are:

| Item | Bytes or members | SHA-256 |
| --- | --- | --- |
| `ubuntu24-environment-dependencies-r2-failure.tar.xz` | 676,080 bytes; 179 payload files plus its manifest | `591d48aaab4f6f6faad675a1d29035baa3e183afc375324df876ab7ed2017841` |
| r2 transfer manifest | Describes 5,345,224 payload bytes | `c90bd3d050544cddd1dad92719bff524238ac9e0ca154c667e13eab2900f06f6` |
| `ubuntu24-matrix-r3-success.tar.xz` | 204,212 bytes; 205 payload files plus its manifest | `0f8913fc69f57f165af3d0d5329e58117357b1b8dee587287d73dfa3639c95f7` |
| r3 transfer manifest | Describes 2,423,967 payload bytes | `b34b2ddab12703958a417742b1a004c4c299bb076c4e849ef1d7687f46712765` |

Both tar files were reopened after packaging and each retained member was checked against its size and digest. Import independently checked the archive and payload identities and preserved their bytes. A manifest proves the identity of the file it describes; it does not turn a generated summary into an original job record.

## Original on-disk job records are the raw authority

The [r3 original-jobs directory](rea-next-ubuntu24-matrix-r3-20261104-r1/original-jobs/) contains nine explicitly selected task directories, each with 12 original files. The [member index](rea-next-ubuntu24-matrix-r3-20261104-r1/r3/sealed/original-job-member-index.json) maps every directory to its original durable job ID and lists the retained filenames.

| Directory under `original-jobs/` | Original durable job ID | Scope |
| --- | --- | --- |
| `environment-prepare` | `1a1a5975a4a-fc05-1fc8` | Pinned Ubuntu image and tool preflight |
| `dependency-cache-copy` | `1a1a5a9cd24-fc05-207e` | Cargo.lock whitelist cache preparation |
| `dependency-fetch` | `1a1a5ae8a6c-fc05-20a3` | Explicit locked Linux dependency preparation |
| `dependency-audit-v1-failed` | `1a1a5b05b2f-fc05-20b7` | Original failed unpack-metadata assumption |
| `dependency-audit-v2` | `1a1a5b37ecc-fc05-20d1` | Independent crate-member byte/hash comparison |
| `matrix-r2-failed` | `1a1a5b446b4-fc05-20d8` | Original noexec container failure |
| `matrix-r3` | `1a1a5c82e93-fc05-216c` | Complete corrected-environment matrix |
| `r2-pack-create` | `1a1a5d1c87e-fc05-21a8` | r2 packaging script creation |
| `r2-pack-execute` | `1a1a5d52366-fc05-21c7` | r2 archive creation |

Each set contains `request.json`, `launch.json`, `owner-intent.json`, `started.json`, `child.json`, `exit.json`, `exit.witness.json`, `stdout.log`, `stderr.log`, the original `runner.py`, and the two original lock files. These are copies of the original files without JSON parsing and reserialization. Their numeric literal representations, request content, terminal values, witnesses and log bytes remain available. These particular jobs supplied their invocation through argv; this list does not assert the presence of a separate stdin file.

For the failed r2 run, use its original [request](rea-next-ubuntu24-matrix-r3-20261104-r1/original-jobs/matrix-r2-failed/request.json), [terminal record](rea-next-ubuntu24-matrix-r3-20261104-r1/original-jobs/matrix-r2-failed/exit.json), [exit witness](rea-next-ubuntu24-matrix-r3-20261104-r1/original-jobs/matrix-r2-failed/exit.witness.json), [stdout](rea-next-ubuntu24-matrix-r3-20261104-r1/original-jobs/matrix-r2-failed/stdout.log) and [stderr](rea-next-ubuntu24-matrix-r3-20261104-r1/original-jobs/matrix-r2-failed/stderr.log). The r2 runner's separate [qualification](rea-next-ubuntu24-environment-r2-20261104-r1/r2/output/integrated-build-r2/qualification.json) remains `qualified: false`. The failed test command and failed outer job retain their respective original exits; they are not converted into successful process results.

For r3, use its original [request](rea-next-ubuntu24-matrix-r3-20261104-r1/original-jobs/matrix-r3/request.json), [terminal record](rea-next-ubuntu24-matrix-r3-20261104-r1/original-jobs/matrix-r3/exit.json), [exit witness](rea-next-ubuntu24-matrix-r3-20261104-r1/original-jobs/matrix-r3/exit.witness.json) and [stdout](rea-next-ubuntu24-matrix-r3-20261104-r1/original-jobs/matrix-r3/stdout.log), together with the runner and container-owner receipts below.

## Derived tool observations have a different role

The r2 archive's `r2/sealed/` directory has mixed provenance. In particular, files such as [r2-original-job-start.json](rea-next-ubuntu24-environment-r2-20261104-r1/r2/sealed/r2-original-job-start.json) and [r2-original-job-terminal.json](rea-next-ubuntu24-environment-r2-20261104-r1/r2/sealed/r2-original-job-terminal.json) were generated from parsed tool-return objects using JSON serialization. The analogous dependency job summaries were prepared the same way. They are useful derived observations of job identity and state, not the original on-disk request or terminal bytes.

Do not use those derived snapshots as proof of exact JSON numeric literal representation, including large integer fingerprints or timestamps. The relevant exact representations are retained in the original records under the r3 archive's `original-jobs/` directories. A filename containing `original` or a directory named `sealed` does not change this provenance distinction.

Other files in `r2/sealed/` include copied fixture source snapshots, tool-observed text, extracted failure blocks and the derived [environment root-cause explanation](rea-next-ubuntu24-environment-r2-20261104-r1/r2/sealed/environment-root-cause.json). Their interpretation must follow their individual origin. The retained [r2 packaging script](rea-next-ubuntu24-matrix-r3-20261104-r1/packaging/pack_environment_dependencies_r2.py) shows how these summaries were produced. The source snapshots and captured logs are not all classified as reserialized JSON merely because they share the directory.

Likewise, the r3 archive's [summary](rea-next-ubuntu24-matrix-r3-20261104-r1/r3/sealed/summary.json), explanatory README and member index are generated explanatory material. Its `original-process-start-response.json` and `original-process-terminal-response.json` preserve tool-response text, which is a tool observation rather than a replacement for an on-disk job record. The [r3 packaging script](rea-next-ubuntu24-matrix-r3-20261104-r1/packaging/pack_matrix_r3.py) records the collection and verification procedure.

## Qualification scope and environment correction

The final r3 [runner qualification](rea-next-ubuntu24-matrix-r3-20261104-r1/r3/output/integrated-build-r3/qualification.json) has SHA-256 `b28e9e47e11e18e99e192ee05abb1034386632a7495002c6bbb18d5097906ab9`. The [container-owner receipt](rea-next-ubuntu24-matrix-r3-20261104-r1/r3/output/matrix-owner-receipt.json) has SHA-256 `f799283e32f9595569daa2a9c0341f418f9930280f2046128c29dd1652eec7ad`. Both report success, unchanged inputs and the successful termination and removal of the owned container. The original intermediate progress snapshot remains unchanged and is not the final qualification record.

The matrix reports 1,886 all-feature Rust tests passed with 39 existing skipped cases, 1,861 no-default Rust tests passed with 27 existing skipped cases, and 441 tests across 21 Python unittest commands. Cached and offline ledger checks exit 0; strict full-parity checking returns its expected 3. These results do not establish complete REA tool equivalence.

The [r2 mount facts](rea-next-ubuntu24-environment-r2-20261104-r1/r2/output/matrix-container-facts.json), failed test output and retained fixture sources show why temporary sudo/SSH shims could not execute on noexec `/tmp`. The [r3 environment correction](rea-next-ubuntu24-matrix-r3-20261104-r1/r3/environment-correction.json) changes only the task-owned tmpfs to explicit exec, retains nosuid/nodev and the original isolation and resource settings, and adds an actual bounded owned-shim execution before the full matrix. Its [observed container facts](rea-next-ubuntu24-matrix-r3-20261104-r1/r3/output/matrix-container-facts.json) preserve that precondition.

The corrected run reuses r2's whitelisted Cargo home and target as a warm cache. It preserves the source, tests, frozen runner, all 35 command arguments and expected exits, zero-retry policy and budgets. The container result is an Ubuntu 24 functional qualification, not a bare-ROG support claim or a physical-ext4 performance result. The separate historical failures remain failed.

Both the before and after inventories bind 295 source files to `9d08a4cc6b6c89f4db47eb300af5e54dd44092082434c93b1dee954c30b2209a` and 613 verification files to `b783c4f05a5c7f614ee7150ecc66bb4fe25f1cfd8ed548723e405e4612b6baa4`.

## Distinct build products and exclusions

| Product | Bytes | SHA-256 and use |
| --- | ---: | --- |
| Ubuntu 24 r3 frozen release | 17,842,176 | `2d021297b50af9eb35bd4d698a90991ec410b2922b707155a506e42125b87442`; product of the complete container matrix |
| Desktop frozen release | 17,820,288 | `4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d`; used by the separate final actual MCP, Chrome and Ghidra external qualifications |

The desktop build is documented in its own [release-only archive](rea-next-release-build-20261104-r2/README.md). Sharing final source and verification inventories does not make these different binaries interchangeable evidence.

The two Ubuntu archives exclude runtime binaries, Cargo cache/target payloads, engine installation trees, user credentials/global configuration and unrelated jobs or containers. Applicable executable paths, sizes and digests remain recorded. This outer index clarifies the unchanged imports; it neither adds a qualification run nor changes an archived success, failure or upstream parity state.
