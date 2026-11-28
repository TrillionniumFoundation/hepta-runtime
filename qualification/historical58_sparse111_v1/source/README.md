# Historical58 checkout closure for installed111

Candidate `c5cbd4d26f2b5ce074b78d77359d903a434139f1` is a four-workflow-only
successor of exact installed `208ff61db1da78aadfeb8d7913af7ddf4b59d461`.
Seven sparse checkout lists acquire the required `runtime_support` directory.
Every other workflow byte, the materializer, profile, 390 production source
files, 119 historical restored files, 7afd and 08ce readers remain unchanged.

The source-only qualification checks all 21 workflows, independently recomputes
both complete 13,257-leaf Git trees, and creates actual local Git sparse
checkouts for all three distinct layouts. Each old layout must reproduce the
missing packed-source refusal. Each corrected layout must materialize and verify
the entire historical source view. Four physical missing/changed-source controls
must still be rejected by the unchanged materializer.

No native graph, Rust compiler, original handler or semantic corpus executes.
The original native CI failure 44000724037 / 133763797882 remains a failure.
The source-only qualification does not relabel any historical semantic result.
Old interrupted local session 13338 is not inspected or replayed.

The complete source input, output, process streams and mutation inventories are
exported and reread byte for byte. A separate guarded reader rejects writes,
metadata changes, subprocesses, ctypes and mmap, then verifies identical before
and after snapshots. Archive hard links are exported as complete ordinary files.
