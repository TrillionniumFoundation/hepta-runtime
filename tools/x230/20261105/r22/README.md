# X230 R22: accepted optimization and evidence index

**R22 is accepted.** For completed-job `process_status` / `process_read`
observation RPCs, six-host C8 successful throughput rose 90.20%, controller
CPU/call fell 60.96% and p95 fell 43.34%. Maximum sampled controller RSS rose
788 KiB (4.43%) within the frozen budget. These rates do not measure new-job
launches or cluster compute throughput. The [full report](../../../../docs/X230_OPTIMIZATION_20261105_R22.md)
explains the source change, conditions, tradeoffs and limitations.

The accepted source/results were published in `afec5354d1e0`. This companion
evidence commit adds the three complete raw archives, verified transfer records
and download links for the same R22 optimization.
[Source publication readback](reviews/source-publication-readback-01.json) binds
the accepted commit, qualified source tree, branch and PR head at publication.

## Results available in this commit

| Record | Scope |
|---|---|
| [Qualification](reviews/qualification-compact-01.json) | Eight stages returned zero; 1,678 selected, 1,644 passed, zero failures/retries, 34 ignored |
| [Actual qualified source map](reviews/qualified-source-map-01.json) | 220 complete compilation-input SHA256 values |
| [Qualification/Git source binding](reviews/qualified-source-binding-01.json) | Full local bytes match the actual qualification and campaign maps; only profile modification and reference-test addition differ from baseline Git |
| [Source review](reviews/source-review-01.json) | Independent implementation/test review, including format readback |
| [Mechanism ABBA](reviews/microbenchmark-01.json) | Five retained targets enumerated; one exact ignored case; 1,536 timed complete file verifications |
| [Final campaign control](reviews/campaign-control-01.json) | Seven successful stages, unchanged inputs/source, passed and adoption_passed true |
| [Campaign gate summary](reviews/campaign-summary-01.json) | Per-concurrency throughput/latency/CPU, sampled RSS, capacity and recovery |
| [Native evidence audit](reviews/native-analysis-01.json) | 2,304 measured +288 warmup +72 preflight/restart =2,664 calls, zero failures; 2,672 RPC frames verified |
| [Capacity evidence audit](reviews/boundary-analysis-01.json) | Two C32 bursts: 32 successes, 32 exact capacity refusals, no other errors; drain/restart passed |
| [Mac holder](reviews/mac-holder-01.json) | Actual holder completion and owned-agent cleanup; [stdout](reviews/mac-forwarded.stdout), [stderr](reviews/mac-forwarded.stderr) |
| [Export 02 receipt](reviews/export-report-02.json) | Actual remote archives/manifests and omitted-body identities |
| [Export review](reviews/export-review-02.json) | Final capture source and closed-inventory/identity checks |

The candidate runtime ELF is 14,371,784 bytes, SHA256
`346b57590211e62ce8732dfcea703c2fae4b2dca5fd62f870c1abd34b1158d20`.
Jobctl and native_process_driver match their accepted R19 identities. ELF
bodies are excluded from the raw packages; remote identity witnesses are not
claims of locally rehashed ELF bodies.

The [frozen measurement plan](measurement-plan-01.json) requires every C1/C8/C16
to pass throughput B/A >= 0.95 and p95 B/A <= 1.10, plus C8 throughput >= 1.10
and controller CPU/call <= 0.90. All passed. Sampled controller RSS was
17,796 to 18,584 KiB, below min(A +2,048 KiB, A *1.15) =19,844 KiB; the per-arm
peak includes two measurement and two restart controllers.

The C6 recovery audit recorded 90 native calls, 36 independent SSH checks, six
new jobs, 12 same-key lookups and 12 cancellations. It is a correctness canary,
not a lifecycle ABBA performance comparison. Capacity refusals remain separate
from successful throughput; C32 client pending does not prove 32 successful
internal admissions.

## Complete original archives

Export 02 and complete archive transfer/manifest verification passed. The
original remote directory remains
`/home/qian/hepta-runtime-optimization-20261105-r22/evidence-export-02/`.

| Archive | Bytes | SHA256 |
|---|---:|---|
| [qualification-01.tar.gz](evidence/qualification-01.tar.gz) | 2,409,428 | `2ca84e7acd2fe7eda2eaaa2d97c9bd16062b3bb4a869e5891b8a2ddc8c83897d` |
| [microbenchmark-01.tar.gz](evidence/microbenchmark-01.tar.gz) | 8,065 | `e166e8c0e1ec18542917b726f557dee91bf168ff5eebd0b96a0049eddd55c0cb` |
| [campaign-01.tar.gz](evidence/campaign-01.tar.gz) | 3,503,622 | `e322e45cd269ae13585f27bf31983c2fe70e7fd05e4b51640531b7297a1ff7d0` |

Each contains an embedded manifest. Qualification has 3,575 payload files and
8 omitted bodies; mechanism has 14 payload files and no omitted bodies;
campaign has 4,106 payload files and 21 omitted bodies. Private profile/config
bodies and the recovery SSH session wrapper are omitted with exact identities.
The campaign package maps the actual R22 recovery directory
`/home/qian/hepta-runtime-optimization-20261104-r16/r22-cancel-recovery-01`
under `recovery/`; older R16 outputs remain intact.

Export 01 failed before its first package because a 540,751,056-byte retained
libtest exceeded the initial 256 MiB streaming-read limit. Export 02 raises
that limit to 1 GiB while still omitting ELF payloads, and rechecks all source
inventories/identities across the three archives. The original code and failure
report are retained. No test or performance workload was rerun for this fix.
The [transfer record](reviews/archive-transfer-01.json) verifies all 92 version-pinned
chunks and complete archive identities. The [tar audit](reviews/archive-tar-qa-01.json)
read all 7,698 members, rehashed all 7,695 payload files and checked exact manifest
membership. Its 29 omitted bodies remain remote identity declarations; this
local archive check does not replay runtime correctness or rehash omitted ELF bytes.

## Tools and identities

New exact tools are the [mechanism runner](benchmark-tools/run_r22_microbenchmark.py),
[campaign launcher](campaign-tools/r22_campaign.py),
[gate summarizer](campaign-tools/summarize_r22_campaign.py), and retained
[export 01](evidence-tools/export_r22_evidence_01.py) /
[export 02](evidence-tools/export_r22_evidence_02.py). The mechanism uses the
retained dev opt-level=1 libtest: thread CPU/verification fell from 2.888286 to
0.181817 ms. Both pins coexist in one process, so this benchmark cannot compare
RSS and remains separate from release RPC throughput.

Qualification source-map SHA256 is
`c998ca803237d1feb8f6ef925bc861171b70969e61602c126ceade8d1acf09b6`.
Campaign size-plus-SHA256 input-map digest is
`a9828a44ef0d8922e6a91dd8a71dadb172a07a4b4156fafab2831aa8b5f889bc`.
The encodings differ and must not be interchanged. Final campaign report SHA256
is `3ec6494b2dc9dd25dbe3650f7becd174b6891aabdc35a4f9f89d16082acfedf7`.

The 2 MiB limit bounds reference payload per profile, not process RSS. One finite
six-host campaign does not establish global optimality. Accepted settings remain
workers=2, arena1 and normal C8. Publication does not change a production
controller service. Actual branch/PR/file-tree readback is performed by the
publisher after the push; the accepted source readback is linked above.
