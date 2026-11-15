# Full CI readback and joint qualification boundaries

This record keeps results tied to their actual Runtime source. The six successful job logs were independently read; tests were not rerun for this review.

| Runtime candidate | Push CI | PR CI | Original joint qualification |
| --- | --- | --- | --- |
| 7924a0c3545125f7a1c3c888adc63f6515668063 | [43016838002](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016838002), attempt 1, success | [43016940004](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43016940004), attempt 1, success | Both original push/PR joint runs PASS; each has 20 source controls, 11 cold checks, 1242 language checks and 10 native/MCP lifecycle checks |
| a0dcdda1991ec536d5e2d252c006a778993fa566 | [43022176834](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43022176834), attempt 1, success | [43022234635](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43022234635), attempt 1, success | [43022234643](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43022234643), attempt 1, failure/HOLD: source controls 20 PASS, cold 6/11 FAIL, language 1242 PASS, native HOLD with empty checks |

For each candidate, the push exact-head job and both PR jobs actually ran. The push prospective-merge job was skipped by its event condition and is not counted as an executed test job.

## Counts read from each actual job

| Suite | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Rust all features, per executed job | 2400 | 0 | 40 |
| Rust without default features, per executed job | 2371 | 0 | 28 |
| Python controls, each exact-head job | 817 | 0 | 1 |
| Python controls, each prospective-merge job | 750 | 0 | 0 |

The feature suites overlap; these counts are not a unique-test total. The Python skipped case is the optional pypdf extraction case, inferred from the exact source's sole skip condition, sorted test order and the corresponding original nonverbose log position. Its reason string was not printed by the job.

All six executed jobs passed format, both check/clippy modes, release build, their applicable Python controls and actual release MCP cancellation/same-owner recovery. Each observed the worker absent at the end without a manual worker SIGKILL. Applicable exact-head REA/ZIP smoke checks also passed within their declared structural scope.

The release Runtime SHA256 was identical across all six observations:
`1a2ed2585ea78fa841b2adbf89fc06f15b9d1fa83dbff62cd94f8a90b6f17964`.
Actual commands used Rust 1.95.0, nextest 0.9.137, all targets, one test thread, retries=0 and no-fail-fast. Prospective merges use each stacked PR's declared base; no default-branch merge or production activation is asserted.

## Original archives and cold failures remain separate

[EVIDENCE_INDEX.json](../EVIDENCE_INDEX.json) binds the original joint runs, source pairs and custody files. The two 7924 ZIPs retain 633/637 source files plus four separately recovered exact-Git workflow files. The a0 ZIP itself contains all 637/637, with no supplement. Its full SHA/CRC, source-byte checks and hidden/private path audit passed.

The a0 cold failure remains QUALIFICATION_TIMEOUT at 180.187798546 seconds under the original 180+3-second budget. Native integration correctly retained HOLD because the cold report was incomplete. Full Rust CI success and archive completeness do not replace that failed HIA qualification.

Machine-readable details and permanent raw-log links are in:
- [runtime7924-full-ci-review.json](runtime7924-full-ci-review.json)
- [runtime-a0dcdda-full-ci-review.json](runtime-a0dcdda-full-ci-review.json)

Whole-worker native status and production deployment remain false. The combined fixed-candidate release decision remains HOLD.
