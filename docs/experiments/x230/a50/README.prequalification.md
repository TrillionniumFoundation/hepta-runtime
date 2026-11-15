# X230 A50 original-reader batches: publication preparation

**This is a preparation skeleton. Final A50 qualification and performance results have not been inserted.** The prepared candidate groups the existing two original readers' channel messages into bounded batches of 32 records. Publishing or adopting an actual result requires the final evidence described below.

| Section | Current evidence status |
|---|---|
| [Design and qualification contract](qualification-design.md) | Frozen design and required checks; no A50 pass claimed |
| [Machine-readable qualification contract](qualification-contract.json) | Final report schemas, receipt links, 19 required test names and counting rules |
| Actual qualification summary | To be generated from final qualification, entry, worker and original test-log bodies |
| Actual tested source map and Git object proof | To be generated from the full 168-file post-format source on X230 |
| Small fixed comparison | A separate result; not established by source qualification |
| Large fixed comparison | A separate result including every failure and original numeric gate |

The input source map is `e348cb3fb70a1d9dde8f97d722e65052c2ffba7807d409a2c822d75c314f4dd0`. It is a preparation identity, **not the future tested map**. Only `request_archive_content.rs` and `request_archive_content_parallel_tests.rs` change from the actual A48 parent. The other 166 source files must continue to match that parent.

The parent is [PR71 checkpoint a9ba701](https://github.com/TrillionniumFoundation/hepta-runtime/commit/a9ba701676138f7e379dab07b38af27c72c46ed8), whose qualified source map is `be631e20eb7ec586c77807bb4e38b6529c5cda1fcc906eb1fac20f793c8c0ff1`. Its [complete A48 large comparison](../a48/large-results.md) remains failed. The [separate A49 diagnostic](../a49/results.md) also remains failed: warmup did not complete, so its 20 measured slots were unexecuted. A49's snapshot timing is evidence about that warmup, not C4 attribution or replacement performance data.

## Publication rule

Use the exact source bodies exported after successful qualification. Do not substitute the prepared overlay, reformat exported source or edit original reports. The source proof must cover all 168 compiler inputs, even though only two source bodies need to be added to the publication commit. Record the actual qualification, entry and worker SHA values, actual release identity, original test summaries and final Git blob identities.

Qualification success and performance adoption must remain separate statements. The small and large comparisons retain their complete fixed schedules, original resource gates and all failed calls. If a required stage, artifact, source proof, measured inventory or numeric gate fails, retain that outcome rather than filling missing results with expected values or selected successful subsets.

The A43 owner-barrier work in [PR72](https://github.com/TrillionniumFoundation/hepta-runtime/pull/72) remains a separately qualified change. This candidate does not combine those source branches. Nothing in this preparation establishes multi-host acceptance, SSH-agent behavior, power-loss durability, steady-state RSS, production deployment or optimization exhaustion.
