# A55: reuse checked filename components and measure complete-scan phases

Status: source candidate under independent review. Qualification, performance
adoption and final integration acceptance remain pending. The parent is the
actually qualified A54 source published at
`34b961941a211025f2083b9fd24470de32cb5b2f`; its 175-input tested source map is
`7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176`.

## Motivation established by the A54 diagnostic

The [complete A54 diagnostic audit](../a54/metadata-diagnostic.independent-audit.json)
retains all original trace events and all 20 attempted calls. The final two C4
waves each split into two independently frozen two-member cohorts. The later
cohorts waited 2,153,089 and 2,118,530 microseconds for the global store lock. Their
remaining complete-original verification budgets were approximately 0.845 and
0.880 seconds; both partial walks stopped at the original three-second deadline.
The corresponding earlier cohorts completed full walks in 2,150,402 and
2,117,846 microseconds. All four later callers failed. The diagnostic does not
establish why the callers arrived late, or the relative costs of allocations,
table lookups, filesystem calls and parsing inside a complete walk.

A55 reduces repeated component construction and adds opt-in measurements of
those internal costs. It does not claim that this local allocation change alone
resolves the independent-cohort serialization problem. The original A54 large
comparison, including its failed candidate warmup and 60 unexecuted slots, remains
failed and is not replaced by this diagnostic.

## Checked component reuse

`read_original` constructs one owned, checked `CString` after the original
canonical filename validation. The same bytes are borrowed by both record
namespace fences, both named stamps and the original `openat`. The new component
entry point derives its filename and shard identity from that same C string;
callers cannot supply an unrelated string/identity pair. Existing string entry
points preserve their validation order and error paths.

All fresh observations remain in their original order: namespace fence, named
stamp, open, descriptor policy and full stamp, complete body read through EOF,
JSON/domain validation, fresh descriptor policy and full stamp, fresh named
stamp, final physical-namespace fence and deadline. Exact held-FD selection,
legacy/shard duplicate refusal, directory-binding fences, original errno
handling, no-follow flags, permissions and ownership checks are preserved.

The normal `read_original` call graph constructs the full filename once instead
of five times without a shard layout or seven times with a layout. Those are
static call counts, not measured allocation or speedup results. The corresponding
ten or sixteen stat/metadata observations are unchanged. No original body,
content proof or completed scan is cached or reused.

## Bounded opt-in phase measurements

The existing `HEPTA_METADATA_TRACE=1` context selects the instrumented serial
kernel once per walk. Ordinary reads and the existing parallel-reader kernel use
a statically dispatched, zero-sized observer. They construct no phase clock,
counter array or per-record trace event.

An instrumented serial walk accumulates fifteen phase durations in nanoseconds,
then rounds only the final sums to microseconds. At the end, including refusal
and partial walks, it attempts exactly eighteen nonblocking events: the fifteen
durations, members attempted, members verified, and whether this scan completed.
The existing bounded trace channel and explicit dropped-event accounting remain
unchanged. No filenames, owners, request identifiers, original contents or error
text are added to the trace.

The phases cover walk/final namespace work, base ROW lookup and decoding, ORDER
validation, pending selection, filename construction, pre-read namespace and
named-stamp checks, open, pre-read descriptor checks, complete reading, parse and
domain checks, post-read descriptor and named-stamp checks, post-read namespace
checks, and comparison/closing work. Inner per-record values and guards drop
before the callback resumes its walk phase. The outer redb transaction and both
tables retain their original lifetime across the complete scan.

These durations are diagnostic wall time, including the cost of timing itself;
they are not pure syscall CPU measurements. The sum starts when the serial walk
is selected. It excludes the preceding transaction/table opening and count or
pending-key prechecks, the final eighteen event sends, and the later table and
transaction drops. `content_scan_complete=1` certifies only that this scan passed
its final namespace fences, coverage and deadline check. Projection, final
snapshot fences and the caller's deadline checks still determine the query's
outcome.

## Validation obligations

The candidate adds behavior tests for reused component opens, changed named
inodes and private-inode policy, and all physical namespace choices. Existing
record-fence tests also exercise the new component path, including exact FD,
cross-namespace duplicates and final directory checks. Timing tests preserve
submicrosecond accumulation, saturate diagnostic output safely, and compare a
successful scan, malformed-original refusal and expired-budget refusal with
their expected complete/partial counts. No test result is claimed here before
the original X230 qualification runs.

The original two-worker/32-task bounds, eight metadata permits, one-millisecond
cohort collection window, three-second absolute product budget, complete
ROW/ORDER checks before pending replacement, writer durability barriers and
original child ownership are unchanged. Fresh qualification must use the
original six Cargo gates, Rust 1.95, two build/test workers, offline/locked
dependencies and unchanged stage/worker/supervisor budgets. Fresh acceptance and
the complete final six-host gate remain necessary before adoption.
