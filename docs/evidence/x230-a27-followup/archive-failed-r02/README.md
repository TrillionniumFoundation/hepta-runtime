# Archive experiment r02: complete publication of a failed run

The native run ended failed, exit 1, with complete captured output. It was not
cancelled by the outer controller and did not hit its outer timeout. The fixed
536-cell plan produced 273 cell receipts: 272 passed and one failed, followed
by 263 not-run cells. The original series labels the failed cell `started`;
that status is preserved even though its receipt contains a cell_complete
event and all eight query rows.

All 2,184 cell-query rows remain, including the two failed metadata queries.
The eight setup queries are separate and all passed. Cell receipts duplicate
stdout events and must not be added to the stdout row total. Cell-0272 is the
baseline A arm at 65,536 records, concurrency four, usage warmup: six passed
and two returned the original metadata-unavailable error. No retry is added.

Both 16,384-record child processes exited zero and emitted complete events
with matching original/final fixture hashes. At 65,536 records A exited 1
and B exited -2; both record sigint_forwarded and neither has a complete
event or final original-fixture hash witness. All four sampler error logs
are finalized, stopped and hash-verified, with zero recorded error JSONL
rows. Sampling ends before final original verification, so its completeness
cannot replace that missing 64K witness. The source/helper inputs-before and
inputs-after agree; those inputs are distinct from fixture originals.

The frozen historical analyzer did calculate and retain partial grouped
and relative metrics, including some true local guard fields. They remain
unchanged in both the complete bundle and the separate full analysis view.
Its overall verified, comparison_valid and diagnostic-performance-gate
verdicts are false. This publication performs no new performance calculation,
does not select the successful 16K subset, and does not use any partial guard
as adoption authority. The candidate is unadopted and runtime source unchanged.

All 323 regular archive members plus the separate terminal/transfer proof
are retained as complete parsed JSON, JSONL records or UTF-8 text lines.
Every original byte hash and all fixed-version transfer chunks are verified.
The six Rust text files are complete sanitized views bound to original bytes,
not a claim that the transformed text is exact compilable source. The private
raw archive and actual identities are not public artifacts. Source/binary
receipts are preserved; binary bodies outside this downloaded archive were
not independently reread locally.

The unchanged frozen A26 CompleteSanitizer supplies string transformations
and opaque hash receipts. Explicit, recorded schema rules cover job/owned
process IDs, transfer versions, file/process stamp aliases, collision-safe
dictionary keys, and loadavg's last PID while retaining its first four fields.
Numeric readable_fields.identity coverage counters stay numeric. Fixed bytes
keys accompanying SHA-256 receipts and errno keys in resource-error rows
keep their technical names despite the generic Cargo crate-name heuristic.
Opaque response/command fields remain present with exact canonical receipts;
they are not decoded for public disclosure. No row, failure, local guard,
sampling scope flag, missing value, or teardown result is dropped.

Read-only inotify limits remain as recorded. Neither direct watch-version
state nor an overflow was observed by this experiment, so this package does
not establish either as the cause. Follow-on phase or branch diagnostics are
separate experiments and are not incorporated here. No workload, remote
operation, runtime change, fixture cleanup, or analyzer rerun is performed
by this create-only publication transformation.
