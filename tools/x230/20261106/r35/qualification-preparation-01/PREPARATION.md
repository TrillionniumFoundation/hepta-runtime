# R35 first qualification preparation

This package is sealed for one future eight-stage qualification on x230. Local sealing checked original bytes and prepared a deterministic deployment archive. It did not launch the preparer, Rust, a test, an auditor, an SSH session, or a benchmark. R35 qualification results, test counts, runtime hashes, CI, and performance remain unknown.

## Source and cache are separate inputs

R35 source comes from accepted R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`, followed by the frozen R35 patch. The complete compiler map has 220 inputs. Exactly `src/mcp/runtime/jobs.rs`, `src/mcp/runtime/ssh_observation_pool.rs`, and `src/mcp/runtime/ssh_observation_pool_tests.rs` change; the other 217 remain identical to R24. The two existing direct test callers receive mutable binding/borrow adapters. No test function or assertion is added or removed. The candidate package is the frozen 29-file package, catalog `4251bcdfb0e5897eaba2ebf3f507f0729e2e3667`, published source commit `d77190730651114c41837228a2180b412713cee3` / draft PR 104.

R34 supplies only its ended `target-build` cache by rename. It supplies no production source. R35 excludes the R34 cancellation reserve and does not import its deferred capacity experiment. The R24 baseline report, original 19 qualification harness files, eight stages, jobs=2, zero automatic test retries, and original 3 GiB free-space minimum remain enforced. Nothing in this package prunes cache files, copies a full cache, changes a threshold, or modifies production services.

## Completed R34 owners

The closure binds the exact 15 original paths enumerated by R34's original rejected-observation postflight, with bytes and SHA-256. Sealing reads 14 original bodies locally, checks their schemas and links, and binds the 3,571,863-byte native observation body through the original closed parent and postflight. The remote preparer must read/hash/check that full original body before cache movement. No original auditor is rerun. The full postflight native status and read are also retained as exact provenance, including complete 4,765-byte stdout and empty stderr.

| R34 owner | Original native job | Recorded outcome |
| --- | --- | --- |
| Eight-stage qualification | `1a1aef7882f-fc05-6499` | Succeeded; all original eight stages completed |
| Exact native Rust CI | `1a1af1ebf1d-fc05-65f2` | Succeeded; 1,653 passed, 0 failed, 34 ignored, 1,687 selected, 0 retries |
| Formal observation holder | `1a1af308953-fc05-6698` | Workflow completed, owned agent reaped; C8 performance gate rejected |
| Original read-only postflight | `1a1af3c8508-fc05-66fa` | Succeeded; source still matched the qualified 220-input map |
| Normal lifecycle / materializer | No job | Both genuinely unrun after the observation prerequisite failed |

These completed R34 counts are historical owner facts. They are not expected R35 counts. The R35 input keeps expected_test_counts null and the seal keeps future job/report/count/binary fields null.

The R34 original parent reports all seven controlled stages closed with actual wait/reap and process/group absence. The original holder report records owned-agent reaping and directory/socket absence. Its native read is bound to the terminal's complete stream sizes. The original native observation has 12 measured cells / 2,304 measured calls, plus 288 warmup and 72 preflight/restart calls; the original independent summary records zero failures. The original compiler audit records 301 samples under its stated 1 Hz sampled scope. Reading these original verdicts does not assert a fresh audit or continuous global machine idleness.

The LC materializer job is null; its started flag is false. The preparer checks that the three normal-LC paths and both materializer native/read receipt paths remain absent. It does not manufacture or require an R33-style failed materializer receipt. The performance rejection remains a rejection: cache-owner closure does not adopt R34.

Root separately completed and published R34 observation archive-02 after the original archive-01 pin rejection, preserving that failure and the three-way pin diagnosis. Those archives are evidence collection and do not change source, measurements, or cache ownership. This preparation does not run an archive collector.

## Runtime preflight and execution order

1. Atomically claim the first `preparation.json`; require fresh source, qualification, and target paths.
2. Verify the caller-pinned input and closure, the launcher identity, all 29 frozen candidate files, the original 19 harness hashes, and accepted R24's current 220-input map against its completed original qualification.
3. Read all 15 R34 original bodies and the frozen postflight. Check actual Q/CI/holder identities, qualified current source/map, original report links, observation controller closure, and the real unrun LC state.
4. Require the old cache to be the expected directory shape and at least 3 GiB free. Check separately retained qualification programs, then inspect readable same-user process cmdline/cwd/exe/FDs for old-cache use and global compiler names. Known opaque system helpers retain the unchanged narrowly scoped classification. Unknown opaque processes stop preparation.
5. Rename the existing R34 cache to R35 with unchanged device/inode, verify the old cache path disappeared, recheck retained program hashes and bound original receipts, and record zero full-cache-copy bytes.
6. Copy accepted R24 source, confirm its original map/harness, apply only the frozen R35 patch with `git apply --check` then `git apply`, and require the exact frozen pre-format candidate map.
7. Invoke the unchanged qualifier once with jobs=2: format, fmt-check, harness-tests, clippy, test-build, isolated-tests, audit-isolated-tests, release. Successful completion must bind actual source_input, source_tested, source_after, and source-map.json; formatting may update the three candidate files, while all other 217 compiler inputs remain exactly the R24 baseline. No pre-format source hash is substituted for the tested post-format identity.

The 13 general preparation helpers are byte-for-byte identical to the successfully executed R34 launcher. The adaptations are the new version/root, the frozen three-path candidate identity, and the actual R34 cache-owner receipt schema and unrun lifecycle state. Failures preserve the first attempt report; the preparer neither retries nor removes a failed attempt.

## Installation and one launch

The archive is create-only deployment input for `/home/qian/hepta-runtime-optimization-20261106-r35`. Its paths are relative to that root; all 39 members are ordinary files. `sealed-01/frozen-preparation-manifest.json` lists the 38 other members and excludes itself. The archive was verified in memory member-by-member without extracting or executing a member. Sealing enforces 64 MiB total/archive, 8 MiB per member, and 8,192 members.

The exact files and identities are in `sealed-delivery.json` and the manifest. Install the complete payload without replacing any existing artifact. The launcher arguments are:

```text
/usr/bin/python3 -B -u /home/qian/hepta-runtime-optimization-20261106-r35/prepare_qualify.py --input-sha256 652541a8f461af9cc7dccd80b5989ffd6e151a8885dea4cc4675f2d054a8be63 --owner-closure-sha256 2bc6f84cc6f26b8f10306b8a7310f21e64b52b6c3a2a86f7191bc239801dcd47
```

The main remote layout is `prepare_qualify.py`, `qualification-input.json`, `cache-owner-closure-inputs.json`, `candidate/` (29 frozen files), `owner-closure-provenance/` (original postflight/native/read), and `preparation-tools/` (local sealer and frozen R34 launcher reference). The reference launcher is evidence and is never executed by the new preparer.

The archive and manifest establish frozen preparation inputs. They do not establish successful R35 execution; the actual native terminal, complete stdout/stderr, original preparation/qualification reports, source-map, inventory/audit, and retained programs will supply those results after the one authorized remote invocation.
