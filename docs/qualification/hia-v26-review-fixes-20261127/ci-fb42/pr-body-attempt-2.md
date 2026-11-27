## Purpose

Bring the completed v25/v26 HIA job-owner work onto one reviewable integration branch. The default branch still lacks the pinned native lifecycle transport, and the v26 candidate branch had no matching CI push trigger. Its Linux-only controller references also prevented non-Linux builds.

The original source history is preserved: `d3d75c3` → `9d12416` → `021f340` → `d022649` → `2d04115` → `55b4422` → `0ce79ce` → `959c680` → `42cc671` → `c967e48` → `6815ec9` → `9b2c2f2` → `fb42bd6`. Current main remains `d3d75c30719db966b004756f610007a7c723729e`; the source history is retained.

## Changes

- Integrate the existing native supervisor and v26 START, READ, STATUS and CANCEL transport, including complete administrator-selected role pins, sealed image custody and bounded request framing.
- Include the existing diagnostic-I/O response repair and complete HIA controller/provider source and contracts.
- Restore `hia/**` push and stacked-PR CI coverage with the existing CI-contract regression.
- Keep Linux native transport admission behind the platform boundary and reject all four native operations on non-Linux controllers before transport. Preserve the portable provider validation path.
- Restore portable checkpoint array-index ordering and its regression coverage; flush the cohort test's pending asynchronous write before its synchronous reader.

The two previously unpublished repair commits change eight files relative to v26: 84 insertions and seven deletions. Follow-up `0ce79ce0e47225073fdc5394651df942eb6b98b1` refreshes 13 existing REA ledger source records and their manifest digest after these source changes, and retains compact source-bound validation receipts. All 229 tool rows, behavior gates, frozen input pins and qualification states are unchanged.

## Review fixes and current CI

Current head: `fb42bd643458e3e1435a0584ba4690ea98071838`, tree `e104f98cdeae7e01f63e93690511b5212ad4e8cf`. The five earlier review fixes were implemented at `959c680`, corrected after two preserved compiler failures, and actually passed their full Rust matrix at `6815ec9`.

- Authenticated HTTP HIA tools retain the original captured POST bytes and cross-check SDK tool parameters and request ID through the native wire observer. Stdio retains its extension-based admission. The real socket test passed for admission and tool/ID/argument mismatches; its fixed descriptor ELF isolates transport binding and does not qualify the HIA parser.
- Native executable pinning accepts safe administrator-selected venv symlinks while preserving original argv and venv semantics. Actual sealed-FD execution and thirteen unsafe-target or retargeting controls passed.
- Controller tests moved into their sibling module, missing copyright notices were added, and production frame decoding uses checked ranges and fallible conversions.
- The REA generator refreshed only affected registered source records. All 229 tool rows and their behavior gates remain unchanged; zero are promoted to qualified.
- The final review finding is fixed by `9b2c2f2cb2eee3948cdaf492104db6a22dec2bb8`: sealed native input creation and rewind run inside `tokio::task::spawn_blocking`. The existing five-second native execution timeout is unchanged. The new sibling test reads the actual descriptor from offset zero and checks sealed mutation refusal. Its exact Rust 1.95 formatting passed on Mac. Its actual Linux descriptor behavior passed in both feature configurations of the push exact-head and prospective-merge lanes below.

### Completed CI at 6815ec9

[The terminal receipt and three complete compressed logs](https://github.com/TrillionniumFoundation/hepta-runtime/tree/fb42bd643458e3e1435a0584ba4690ea98071838/docs/qualification/hia-v26-review-fixes-20261127/ci-6815) retain all original job metadata and actual test lines.

| Lane | Actual result |
| --- | --- |
| [Push exact head](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45953858742) | PASS; 2,656 all-features and 2,614 no-default tests passed, with 44 and 32 existing skips |
| [PR exact head and prospective merge](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45953867303) | PASS in both lanes, same test counts; last exact lane ended 2026-11-27T08:23:08Z |
| Repository Hygiene, push and PR | PASS |
| HIA helper contract | PASS |
| Existing old common-candidate workflow | HOLD / failure at catalog equality against old Hepta 7c20; retained and not counted as a pass |

All five added Rust tests actually passed. Each selected release, JavaScript cancellation/recovery, parser/syscall-denial and independent ZIP gate completed. These results qualify the observed `6815ec9` source, not the later asynchronous preparation fix.

Earlier E0277 at `42cc671` and E0433 at `c967e48` remain recorded with original full logs. The final dependency-free standard-library hex expression is the one validated by `6815ec9`. The Mac offline missing-dependency failure, original online download observation, and formatter-path failure are also retained.

### Observed CI for fb42bd6

| Lane or gate | Actual status |
| --- | --- |
| [Push exact-head job 140394130778](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45965822403/job/140394130778) | **PASS**; 2,657 all-features tests and 2,615 no-default tests passed, with 44 and 32 existing skips; all selected release gates completed |
| [PR prospective-merge job 140394155815, attempt 1](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45965830223/job/140394155815) | **PASS**; the same two test counts and original selected release gates completed |
| [PR exact-head job 140394155394, attempt 1](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45965830223/job/140394155394) | **FAIL**; all-features ran 2,657 tests: 2,656 passed, one failed, 44 existing skips. No-default and later gates were not run in this lane |
| [One diagnostic retry, run 45965830223 attempt 2](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45965830223/attempts/2) | **in_progress**, exact same head `fb42bd643458e3e1435a0584ba4690ea98071838`; only the failed job was requested through the official job-rerun API |
| [HIA native helper contract 45965830240](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45965830240) | **PASS** in both feature configurations |
| Repository Hygiene 45965830200 / 45965822363 | **PASS**, PR and push |
| [CodeQL 45965824509](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45965824509) | **PASS** |
| [Existing common-candidate 45965830222](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45965830222) | **HOLD / failure** at the old common candidate's catalog equality; retained and not counted as a pass |

The original failed test is `isolated_actual_ssh_guard_cancellation_and_ownership_fixtures`, inner fixture `agent-timeout-then-io-error`. It failed during the original actual-SSH initialization, before the injected agent fault, with `observation SSH pidfd or post-exec identity refused; no fallback`. Its complete original 621,401-byte log is retained with SHA256 `6703c781baab986f64c6bfea6d74e9a715021923f2e7b85f1ab3ac6db51e9ef5`. No fixture, identity guard, source, deadline or expected result was changed. The one same-head retry is diagnostic; this first failure is not relabeled as a pass or declared flaky.

The new sealed-input regression and HTTP admission regression actually passed in the original failed lane as well as the two successful lanes. The final PR exact-head lane still must complete its original required checks before merge. All six review findings are implemented and have source and actual test evidence; the separate unpublished native-common framework, Hepta F/D artifact admission, public activation and old-stack removal remain outside this PR's claims.

## Actual validation at 55b4422538019a02f750a49bd03ed3b89df3aa06

Fresh isolated macOS ARM64 checkout, tree `491bcf00734d652afa1c10ca47f00a0fa23e7919`, Rust 1.95.0:

| Check | Observed result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS, 1.116 seconds |
| Existing runtime CI-contract suite | PASS, all 6 tests |
| `cargo check --offline --locked --all-targets --all-features --jobs 2` | PASS, 60.646 seconds |
| `cargo test --offline --locked --all-features --lib native_jobs -- --nocapture` | PASS, all 7 tests, including non-Linux refusal for START/READ/STATUS/CANCEL; 215.410 seconds including test-profile compilation |
| Tracked source custody | Unchanged isolated source; the original worktree was not modified |

The original run [45938922030](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45938922030) actually passed both all-target feature checks and both Clippy configurations. It is superseded by the substantive ledger repair, not reported as a complete matrix pass. Repository Hygiene [45939112755](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45939112755) failed on the stale source projection; its original failure is preserved.

## Retained baseline validation at 0ce79ce

[Source-bound qualification directory](https://github.com/TrillionniumFoundation/hepta-runtime/tree/0ce79ce0e47225073fdc5394651df942eb6b98b1/docs/qualification/hia-v26-platform-ci-20261127) retains the Mac commands, complete log identities and original durable job terminal result, the initial hosted CI failure, the exact 13-record mapping refresh, and all local mapping-test results.

The refreshed ledger passes `check-mapping`; strict parity still returns its expected exit 3; all 29 ledger integrity tests pass. The complete REA consumer suite in the scratch container ran 362 tests: 361 passed and one errored because that container lacks `/proc/<pid>/task/<pid>/children`, preventing the real owner/drain observation. This failure is retained; no test was weakened or skipped. The hosted Ubuntu Repository Hygiene job subsequently passed the complete retained REA consumer step on the old `0ce79ce` head.

Historical baseline head: `0ce79ce0e47225073fdc5394651df942eb6b98b1`, tree `1526ac3bc635661871669c1d692c656169647bdf`.

- [Push exact-head matrix 45940072062](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45940072062): **PASS**. Both all-target and Clippy configurations passed; nextest reports 2,651/2,651 all-features tests and 2,610/2,610 no-default-features tests passed, with 44 and 32 existing skips respectively. Descriptor-relative safety, REA mapping/evidence, control-plane, X230, unbounded ingress, release build, JavaScript cancellation/recovery, shipped-binary parser/syscall denial and independent ZIP writer checks also passed. The push event's prospective-merge lane is correctly skipped.
- [PR exact-head and prospective-merge matrix 45940078188](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45940078188): **PASS in both lanes**. Prospective merge `238ff1372f13eb32d08a488f56e879f184f71a06` and exact source head each passed both all-target and Clippy configurations, 2,651/2,651 all-features nextest tests and 2,610/2,610 no-default-features tests, with 44 and 32 existing skips respectively. Both completed their selected safety/evidence, release and JavaScript lifecycle gates; exact head also passed the shipped-binary parser/syscall-denial and independent ZIP writer gates. The final exact-head job completed at 2026-11-27T06:03:51Z. Skips are not counted as passes.
- [Repository Hygiene 45940078278](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45940078278): **PASS**; both push and PR jobs passed on the old `0ce79ce` head, including the refreshed mapping and complete retained REA consumer step.
- [HIA helper contracts 45940078133](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45940078133): **PASS** in both feature configurations.
- [HIA common candidate 45940078307](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45940078307): **HOLD**; the selected old Hepta hosted cold run reached its unchanged 180-second deadline and the owner killed/reaped its children; independent language coverage passed 1242/1242. Integration correctly refused the incomplete cold report.

Raw reference authentication was not rerun successfully for this source-only projection refresh. Historical raw-byte pins and behavioral qualification receipts retain their original scope.

## Common-candidate mismatch found in the retained original run

The original common-candidate run [45939112683](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/45939112683) completed cold replay **11/11** and language coverage **1242/1242**, then held before any MCP session because the workflow still selects Hepta `7c20b6cfc792f0147b5418968f94734b8890fcca` while v26 changed the Runtime catalog.

Artifact `15172480524` (SHA-256 `970c19631e70d9fb896fe1a33a3848ee883b7a7c0556e0e4b55ca8ae54311a22`) retains the exact error: `Runtime and Hepta do not share exactly the same catalog bytes`. The current Runtime catalog SHA-256 is `b6b8054ce46ae9ceac260e99a3d1beaf5d6c9343bc4c6e5d96281eedd3c3edfd`. The integration must select and qualify a published Hepta candidate with the same actual catalog bytes; the equality gate remains intact. The latest Hepta source uses a separate native-v2 cold domain with a real 60-phase native chain. Its native report admission and formal release helper outputs must replace this workflow's old hosted cold/helper builder together; merely changing the source SHA or renaming a receipt schema would be invalid. The original language fixture inventory and assertions also remain required: the 60 native cold phases are not assumed to subsume the separately retained language witnesses. A native-cold B3/M3 execution path is being prepared for those same fixtures, with the external reference timing recorded separately from the cold before-B0 gate.

## Remaining integration gates

`whole_runtime_replaced`, production activation, fresh integrated Store/public-tool qualification and old-stack removal are still unqualified. The v25 retained-Store 39-call/11-tool evidence keeps its original source scope. The v26 transport still requires its fresh Worker installation and full public-tool campaign. This PR makes the existing source and its actual platform repair available for integration without promoting those remaining gates.
