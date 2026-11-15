# Streamed exact-key lookup for Hepta Runtime (2026-10-16)

**Isolated candidate only.** Stacked on PR #13's positive-cache and PR #12's host-scoped launch lock; not deployed to any of the six production hosts.

## Bottleneck

The original `find_idempotent` called `all_records_in`, which reads every JSON job record, allocates a full Vec and sorts by creation time even though the caller only needs an exact configured-host/idempotency-key match.

On the actual R22 host, a read-only directory observation saw 23,347 JSON job records and 46,257,139 bytes. The six-host no-op launch batch was 29.071 s, and an exact six-key reuse batch was 29.717 s at the ChatGPT/plugin boundary. Neither number can be assigned solely to Rust scanning.

## Changed

`scan_idempotent_binding_in` now streams the directory without allocating or sorting all original JobRecords. It still fully deserializes **every** original `*.json` record, rejects corrupt unrelated history, and refuses any duplicate `(host,key)` binding. It does not skip early, negative-cache misses, write a disk index, allocate a new job identity or bypass the original host-scoped launch lock.

`all_records_in` remains available for complete sorted inventories. The existing positive-hit cached read retains the strict single-link, current-UID-owned `0600`, `O_NOFOLLOW`, bounded-size, before/after inode identity checks from PR #13.

## Qualifications and known limits

New focused streaming equivalence and corruption/duplicate tests: **2/2 PASS**. On the same disposable 6,000-record dataset, an explicitly ignored alternating-order microbenchmark observed median **74.264 ms** for original fully sorted lookup, **61.920 ms** for streaming full-validation lookup (about 16.6% lower), and **0.080 ms** for an already-known original ID's positive cache hit. The first cold lookup in that run was 377.287 ms and is not directly comparable with warm medians. These are local filesystem measurements, **not** SSH task launch TPS, a production p95 result, or evidence of R22 speedup. Exact isolated-source locked Cargo regression completed: **660 main-Runtime tests passed, 0 failed, 13 ignored**, plus **8 Jobctl tests passed**. `cargo fmt --check` and `git diff --check` passed. These results do not qualify a production R22 upgrade.

No trustworthy source-commit binding has been established for the running R22 native binary. Source files from one unversioned local replay tree match 35/37 located release files, but the actual HTTP adapter and registry pager are two mismatches; the Rust binary has not been reproducibly built from a pinned commit.

Do not merge or deploy without a single effect owner, cross-controller idempotency reconciliation, isolated six-host 1/4/8/16/32 A/B, controller recovery and rollback. No production V4/V11, OpenAI tunnel or Desktop Commander process was changed here.
