# R36 static optimization frontier

This note reviews source choices. It does not attest a performance result, candidate adoption, hosted CI, or a new remote experiment. Original qualification and campaign reports remain authoritative for their own outcomes.

## Selected minimal candidate

R36 starts from the accepted R24 production source, checked out at Git parent `86155fbf3b89e5a77e2a4aadebd2128c663fe50b`. The production change replaces two final `cache_hot(&directory, &records)` calls with `cache_hot_owned(&directory, records)` in `src/mcp/runtime/request_audit.rs`, in `begin_with_read_at` and `begin_reserved_record_at`. The existing batch implementation already uses this ownership helper.

Both paths have finished using the owned `Vec<Record>` at that point. Moving it into the cache eliminates the second full record/vector copy on successful admission. The first `hot_snapshot` copy remains. This is an allocation/copy reduction; its net throughput, latency, CPU and RSS effects require the original R36 measurements.

The replacement occurs at the same publication point. Archive and hot-file writes, fsync order, durable identity fencing, admission limits, lookup pins, owner boundaries, cancellation, unknown-result handling and shared read paths are unchanged. Two neighboring tests were extended for refused lookup owner/cache isolation and archived-identity duplicate recovery; their test count was not inflated by adding mirror tests. The frozen qualification must bind the actual formatted source, not just the pre-format input map.

## Rejected or excluded directions

The initial proposal to consume the hot cache at the beginning of these two exclusive paths was rejected before candidate freeze. A purely refused lookup or archived duplicate would then empty a useful cache and force the next admission to reread the bounded hot set under the store lock. The store permits 128 records per owner and 512 globally; avoiding one copy did not justify that new rejection-path cost. The rejected proposal is separate from the candidate patch.

Router-only caching, legacy read-JSON deferral and command `mem::take` had already been trialled separately by the main campaign. They are not part of R36, and this static review makes no replacement claim for their original reports. Increasing reference buffers, relaxing validation or performance gates, raising concurrency limits, removing fsync, weakening durable identity fences, or simplifying cancellation/unknown-result semantics are not justified by this change.

## Plausible remaining costs and limits

- The initial bounded hot snapshot still clones records while exclusive admission holds the store lock. A deeper immutable/shared representation might reduce copying, but would change more ownership and error-path behavior than this candidate. It needs direct evidence that the copy remains material.
- Durable audit publication still performs file and directory synchronization. The existing batch/group-commit code already shares some work. Further batching must preserve individual durable acknowledgement and recovery boundaries; a shorter critical section cannot be assumed safe merely because it improves a synthetic timer.
- SSH observation still validates pinned profile/reference identities and uses bounded masters, sessions and queues. These checks, direct SSH lifecycle work and cancellation/recovery can dominate small RPCs. A faster allocation path does not establish that any full verification can be cached away.
- The observation pool and direct transport have explicit capacity bounds. More admitted work can increase queueing, process count and RSS on X230. Sustainable capacity must be judged together with tail latency, resource use and cancellation behavior, rather than by throughput alone.
- Multi-host latency and contention include the remote machines, SSH processes, storage and competing load. A finite frozen host set and concurrency matrix cannot prove that no further optimization exists, or that a result holds for every saturated workload.

These are source-based hypotheses, not measured bottleneck rankings. The justified stopping boundary for this round is the smallest candidate that satisfies the unchanged qualification and performance gates with complete retained evidence. The asynchronous read supplement is descriptive and does not create an additional adoption gate or a saturated-cancellation claim.

Source references: `src/mcp/runtime/request_audit.rs` (`MAX_OWNER`, `MAX_GLOBAL`, `hot_snapshot_at`, `cache_hot_owned`, both admission paths); `request_audit_batch.rs` (cohort snapshot/publication); `request_audit_sync.rs` (bounded sync workers); `ssh_observation_profile.rs` (pinned profile/reference validation); `ssh_observation_pool.rs` and `ssh_direct.rs` (bounded admission/session/connection machinery).
