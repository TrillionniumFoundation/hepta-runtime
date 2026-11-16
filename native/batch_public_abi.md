# Public local Batch integration (development qualification)

The graph extends the eight-tool public graph with batch_edit and compiles 71 physical HIA members. Config17 and publisher physical image10 remain unchanged. The extra table has37 fixed private slots:33 Batch gateway,34 actual Batch typed owner,35 callable Batch engine,36 supplemental HIA catalog. The View table has19 entries; the independent Batch table has22. No public JSON selects a descriptor, image, pointer, epoch, lease or Session instance.

The frozen v20 inner caller owns request scope, locks, strict reads, History, atomic publication, NoteWrite, Diff and hint drain/append. The outer gateway performs actual typed admission, effect-fence acquisition, Session/workdir and outer path policy. Empty/>50 operation errors come from the real inner owner after outer policy; they skip path resolution and I/O. The outer copies the complete final body before releasing its fence permit. The publisher separately acquires the entire body before any engine reuse.

Each Session's Batch cache/lease is the existing View slot8/slot7 arena. Trusted installation drops the empty Batch context, releases its initial private cache lease, borrows the current View arenas and obtains a real lease CLONE. Every call refreshes and writes back moving arenas. Retirement releases that real clone, restores originally owned mappings and only then frees the Batch engine. All Batch engines share one retained History/LockState primary per process.

Production leaves inner fixture fields+24/+96 zero. Pending read/atomic workers are actually joined before consuming their output or retiring their arenas. Queued locks remain an unfinished public async-dispatch domain in this graph. SDK cancellation notifications are distinct from private future cancellation. Remote Batch success and configured-fence authority coverage remain unqualified. This graph does not claim the full original catalog or full HTTP dispatcher.

## Private observation carrier

The separate fixture ELF retains HFSFXQ02+3*u64(Session0/1,selector,payload_len) and existing selectors0..34. Selector34 invokes the same actual frontend and publisher. Selector33 observes exact Session/cache/context/scope/lease state. The public stdio executable does not link these private controls.

Selector35 has empty payload. It returns HFSFXR02, return0, then HBCOBS03: a192-byte header followed by complete caller, global History and global LockState workspaces, then the actual Batch request-context64, scope256 and shared lease256 prefixes, in that order. Header u64 offsets:

| Offset | Field |
| --- | --- |
| 8 | flags: global1, binding2, same cache arena4, same lease arena8 |
| 16 | binding phase |
| 24 | Batch retired flag |
| 32 | actual worker PID |
| 40 | global borrowers |
| 48 | Session borrowers |
| 56 | caller workspace capacity |
| 64 | History workspace capacity |
| 72 | LockState workspace capacity |
| 80 | caller used bytes |
| 88 | History used bytes |
| 96 | LockState used bytes |
| 104 | actual clone epoch |
| 112 | actual clone ticket |
| 120 | View epoch |
| 128 | View ticket |
| 136 | pending target |
| 144 | caller phase |
| 152 | zero |
| 160 | Batch context prefix length:64 when bound, otherwise0 |
| 168 | Batch scope prefix length:256 when bound, otherwise0 |
| 176 | Batch lease prefix length:256 when bound, otherwise0 |
| 184 | zero |

Absent owners have zero lengths. Observation never creates or invokes an owner. Complete caller/History/LockState workspace capacities are captured; readers parse used prefixes under the actual HIA schemas and retain the complete remaining bytes. Context/scope/lease prefixes are read directly from this Batch engine slots10/6/7, not inferred from the View engine or response. The same-lease flag separately checks the real shared arena and private epoch/ticket fields. The older development HBCOBS02 capture remains unchanged and is not accepted as this192-byte record.

Selector36 payload is HBCNEW02+u64(raw_root_len)+exact raw PathBuf bytes. It retires one fixture Session/Batch/View and creates a fresh Session with the same real process config/fence hub, using HRSWQ002 INIT on those exact bytes. It never chdirs, getcwds or canonicalizes the root. The response is the real HRSWR00232-byte unit, framed by HFSFXR02. Its six counters belong to the new Session's initialization. Existing global History/locks remain alive. Original comparison uses this only to initialize each fresh per-scenario process; it does not equate cross-scenario retained globals with a fresh original process. Ordinary public stdio startup cwd and BrokenPipe observations remain separate.

The unique public input generator contains133 steps in15 scenarios. Its original carrier explicitly constructs SessionWorkdir from raw PathBuf, with one fresh original process per scenario and two real Sessions where declared. It executes the original SDK adapter and method, not the complete original tool router. No original public Batch comparison has run for this development graph. All complete-runtime flags remain false.
