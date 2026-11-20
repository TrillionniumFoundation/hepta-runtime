# Qualified isolated HIA binary write request adapter

This change supplies the real HIA byte adapter between the installed binary call
planner and the separate binary parent owner. HIA owns input validation, retained
continuation state, complete fixed-child result comparison and construction of
the parent's `HBPWQ001` request. The executable source and private ABI are in
[`source/README.md`](source/README.md) and [`source/ABI.md`](source/ABI.md).

The adapter invokes the unchanged actual HIA planner through a private
qualification carrier and compares its entire result, including all JSON bytes.
It copies the admitted typed/root byte extents into the parent request only after
that comparison succeeds. An empty expected version remains present. Raw UTF-8,
NUL, path and Base64 bytes stay intact. No FD or callback address is supplied by
the request. The fixed parent input interface is `HBPWQ001`, not the parent's
outer qualification carrier `HBWTFQ01`.

## Actual complete qualification

| Check | Actual result |
| --- | --- |
| Frozen source | 38 files, manifest `1c38b08d610c2440ae2e246bc06519f416591bbca590850f758ea8eef5848d4a` |
| Fresh fixed-B3 compilations | 4 images in 5.969817370 seconds |
| Complete processes | 27 natural successful exits in 32.222061536 seconds |
| Original planner domain | All 433 inputs in all 24 original groups, including 59 writes and 19 ready writes |
| Original typed write domain | All 196 write inputs from the original 1,388-case typed domain |
| Parent input projection | All 256 inputs: 254 complete packets and 2 original null-to-String rejections |
| Private boundary domain | 50 exact physical refusals, 2 actual fixed-child mismatches and the complete 16-event lifecycle |
| Complete native journal | 6,715 entries; 674,302,345 logical bytes of full input/output/workspace records |
| Independent reader controls | 14 tests, retaining the original 7 and covering packet substitution, return/capacity/identity changes, lifecycle reordering and stale sequences |
| Unchanged original DATA guard | 11 capability probes; 1,461 entries identical before/after; 4.930870341 seconds within the original 180-second limit |

Every process keeps its 60-second bound and 5-second cleanup bound; the complete
capture keeps its 1,800-second limit. There was no timeout or cleanup. The
compiler is the exact retained `d3e2c90173cf733e42b299d0c4274df4b593a12f`
source, with B3 `bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
The actual typed and planner images are byte-identical to the installed #135
images. This work does not claim a new compiler cold bootstrap.

`RESULTS.json` records the exact source, image, run and guard identities. The
parent ABI snapshot and domain are preserved in `source/parent-interface`; their
authority is limited to the input bytes used here. The parent projection does
not execute its fault plans, FD actor, writes or resource controls. It does not
requalify the parent's 256 effects or the historical body101.
`PARENT_INTERFACE_LINK.json` also binds that snapshot to the independently read
current 57-file parent R3 source. The full domain and parent HIA bytes match;
two exact reversible documentation edits describe actual `openat` mode zero and
the observing parent's SIGCHLD wakeup pipe. The complete request ABI text is
unchanged. This source association takes no credit from its running capture.

## Preserved earlier evidence and precise reader repair

The first capture and all its original receipts remain in the archive under
`runtime-audit/binary-write-adapter`. Its `READER_GAP.json` records the specific
review finding: the first reader accepted producer-provided control labels and
expected returns without independently binding every exact refusal input and
all lifecycle request positions. Its original DATA receipt is retained verbatim
and does not qualify this later source.

The corrected source independently reconstructs all 50 refusal packets, initial
buffer capacities, complete initial workspace and expected return. It binds the
16 lifecycle events to exact ordered requests, generations, retained owner and
fresh planner contexts, complete publications and every physical growth record.
All 85 control invocations must occur in their original order. The original 53
cases, capture worker, HIA bytes, native images, guard and limits are unchanged.
`SOURCE_CHANGE.json` and `reader-identity-r2.patch` describe the exact reader-only
change. Four archived control-fixture files support DATA regression tests and
give no new native execution credit.

The new source was then compiled and run in full. The earlier and intermediate
source snapshots are retained inside the evidence archive, with only the final
38-file source exposed as the reusable source tree in this directory.

## Restore and independently read the actual evidence

Run these from this directory, supplying a fresh output directory and a checkout
that contains the unchanged #135 archive parts inherited by this branch:

```sh
/usr/bin/python3 -I -S -B restore_capture.py \
  --output /absolute/new/adapter-restored \
  --parent-checkout /absolute/current/runtime-checkout
```

The archive retains every source file, all 1,080 compiler inputs, complete real
compile inputs/outputs/receipts, full process streams and full native journals.
`EVIDENCE.json` binds every archive part and the full logical file inventory.
Restoration verifies every logical file's bytes and mode, plus the unchanged
seven historical #135 parts. It does not rewrite recorded semantic origins.

After restoration, the unchanged strict reader runs directly on the restored
source and capture without native, compiler or Rust execution:

```sh
/usr/bin/python3 -I -S -B \
  /absolute/new/adapter-restored/restored/runtime-audit/binary-write-adapter-r2/final-source/scripts/guarded_read.py \
  --images /absolute/new/adapter-restored/restored/runtime-audit/binary-write-adapter-r2/actual/images \
  --capture /absolute/new/adapter-restored/restored/runtime-audit/binary-write-adapter-r2/actual/capture \
  --source-sha256 1c38b08d610c2440ae2e246bc06519f416591bbca590850f758ea8eef5848d4a \
  --capture-sha256 711791d08c0e9b227d34defde626619c437a90c544171c6d94b03f235486485a \
  --output /absolute/new/adapter-restored/READBACK.json
```

`RESTORE_VERIFICATION.json` records the actual local archive restoration and
guarded read. The smaller source-only check is `../read_source.py`; the complete
reader regressions are `source/tests/test_reader.py`.

## Product boundary

This Draft is an isolated successor to #136. It changes no existing product
source, graph, registry, handler, workflow, budget or original route. There are
still 13 public native routes out of the original 136-tool target. The new
adapter's production carrier, real parent/body composition, authenticated Host,
audit, SSH transport, cancellation and lifetime integration remain separate
work. `production_carrier_installed`, `host_audit_ssh_lifecycle_qualified`,
`public_binary_write_registered` and `whole_runtime_replaced` remain false.
No Rust or other still-owned stack is removed. Normal GitHub CI runs separately
from the recorded local qualification and must be assessed on its own results.
