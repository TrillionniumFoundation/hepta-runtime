# A26 64K archive deadline frontier: source diagnosis

This is a source review and a fixed next diagnostic, not an attributed root
cause or a repair. No remote call, Rust build, new runtime measurement, old
fixture deletion or installed-runtime change was made here.

## Actual observed failure

The preserved `cell-0272` receipt is 7,159 bytes, SHA256
`b9d0d3334edcb150532b8b2af69c19477d2cfb6165700348ae883b71a6edc52b`.
It is baseline A, 65,536 originals, warmup usage, C4, eight requests. All eight
rows are present: six successful responses and two public errors. The two
four-request waves finish at roughly 0.9, 1.8, 2.7 and 3.0 seconds. Their summed
process CPU is 6.001846812 seconds and wall time 6.000470767 seconds. This shows
substantial process CPU during serialized progress; it does not identify a
function. The generic public error masks several internal failures and does
not, by itself, prove index rebuild, permission loss or timer origin.

The runner stopped following cells without retry. No successful 16K subset is
used for relative gains, and no original performance gate is re-evaluated here.

## Concrete full-scan branch

In exact A26 `request_archive_index.rs`, `read_snapshot` holds `STORE_LOCK`
and the slot state guard through validation, result construction and final
acceptance. At its `state.version.is_none()` branch it calls `verify_members`
for **every query**. That function walks all original members, looks up ROWS,
decodes each derived entry, checks the original stamp and ORDER projection,
then compares exact table counts. `Archive::walk_members` spans the legacy
directory and all 256 shard directories with full layout fences. This is
genuine O(N) work under the authority lock, consistent with the observed
scaling and queue delays if the branch was taken; branch execution is not yet
directly observed.

The healthy watched path does not run that member scan. Its usage body reads
three state counters, active registrations, the owner's tool counters and
ORDER endpoints. The fixed fixture has four tool names and does not register
active dispatches; no pending cohort was intentionally published. An existing
layout's `fence_at` uses `validate_layout(false)`. A healthy, drained
`ContentWatchSet::version` checks its one event stream and at most 258 watch
entries, not 65,536 directory children. Those findings narrow the diagnostic
priority to watch availability/fallback and serialized authority work, rather
than allocating the 588-byte response.

## Lost-watch mechanism and fixture lifetime

Exact A26 `namespace_version.rs` creates a **single** inotify stream for the
258-directory composite scope; this limit is distinct from ordinary
`MAX_WATCHES=128`. Content masks include create, modify, close-write and
attribute changes. `Watcher::changed` marks all watches dead on
`IN_Q_OVERFLOW`. `ContentWatchSet::version` marks the set permanently invalid
after a drain error or any dead watch and returns `None`; later calls return
`None` without re-arming. The existing
`lost_composite_events_disable_reuse_permanently` test injects overflow,
ignored and unmount events and requires repeated `None`. That test is source
evidence of intended semantics, not proof of an overflow in this experiment.

The frozen probe calls `initialize_shards` before bulk-seeding its originals.
The seed loop writes directly through `write_fixture`; it does not use the
normal publication wrapper or drain `content_version` between records. The
first slot/readiness version is obtained after that loop. `Fixture` retains
both `Archive` and its original `Arc<Slot>`; the slot also retains the archive.
`STORES` upgrades the same `Inner`, whose `OnceLock<Layout>` already contains
the watch set. A lost set therefore persists through that process's cells;
rebuilding the disposable index does not install a new scope.

This is a concrete possible chain from bulk seed to a permanently unwatched
fixture and per-query full scans. Actual queue overflow, setup watch failure
or another lost-watch event remains unobserved. Read actual inotify limits,
retain the failed evidence, and avoid treating a common kernel default as a
measured value. A future watch-health diagnostic must not consume or re-arm
the event stream and silently alter the workload being diagnosed.

## Existing trace and smallest next slice

The injected `main` hook returns into the probe before CLI handling and
`init_mcp_logging`. `HEPTA_REQUEST_AUDIT_TRACE` uses a tracing subscriber and
API flushes that these metadata calls do not provide, so it is not a reliable
diagnostic here. Conversely `HEPTA_ARCHIVE_INDEX_TRACE=1` enables direct
stderr `SteadyTrace` output and needs no subscriber. The frozen series runner
strips that variable; the new fixed driver injects it only into one verified
original A launch.

See `PLAN.md`: fresh 64K fixture, two unchanged setup queries, eight C1 usage
and eight C1 history queries, complete output and original-child teardown.
Dominant `snapshot_read_us` with small state/lock phases supports investigation
of the full scan; dominant state/watch or uncovered preparation time points
elsewhere. The trace lacks a `version_is_none` field and scanned-member count,
so it cannot prove the branch or historical overflow. If that distinction is
still necessary afterward, a separately frozen probe-only diagnostic can
record the already-held slot state without calling `content_version` again;
an overflow counter would require explicit instrumentation at the event
handling site. Neither change belongs in this existing-binary slice.

All fences, the original three-second deadline, retained blocking-worker
permits and failure behavior remain intact. Automatically re-arming a lost
watch is not proposed: the missed-change interval is precisely why this
implementation refuses cached authority.
