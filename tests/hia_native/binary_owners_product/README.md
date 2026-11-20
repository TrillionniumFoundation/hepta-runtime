# Installed binary-write parameter and call-plan owners

This successor to PR #134 installs the previously qualified HIA write-parameter
owner and HIA call planner in the real default runtime image table. The original
13 public routes remain unchanged. Public `binary_write` still returns `Unknown
tool`; remote effects, audit, cancellation and complete handler ownership remain
unqualified. No Rust implementation or historical evidence is removed.

## Exact source and layout

The base is `1f652e301f01bd8a99dc9b0c272b5037ac319515`.
The original compiler remains Hepta
`d3e2c90173cf733e42b299d0c4274df4b593a12f`, B3
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.

| Installed member | Slot | Qualified source commit | HIA SHA-256 |
| --- | ---: | --- | --- |
| `binary_write_params` | 69 | `0666613d8c3cad74f6eb192c287069988e813827` | `f1779101f1edf27e0e8dd384f14f88b4ae877392b02b2c772105fbf5645e693b` |
| `binary_call_plan` | 70 | `5535171a52aa724f8c4b6974450deec9720dc210` | `fc8624cc760735a0fdaea46fb5c7434c09cc1fe96d8b218d510a3858fe3305bc` |

Both HIA files, their compositions and ABIs are imported byte for byte. No HIA
policy is reimplemented in the assembly bridge. The bridge validates complete
ABI headers, reserved fields, kind and extent, and handles the existing growth
contracts. All 116 previous direct images and the ordered original 69-slot
table remain byte-identical.

The new graph has 118 direct plus 8 packed HIA members, 119 physical images and
71 descriptors. The 16,384-byte engine remains the same size. Its descriptor
table ends at 12,736; high allocation bitmap words move to 12,736 and 12,744.
Keeping the old offsets would overlap the new slot-69 descriptor. The source
binding is `280261f2df19a9b0ba988b984ddf8d70e3c77efe68c7a908cb9348db952a1cb7`.

`SOURCE_FREEZE.json` and the native integration composition bind every source
and the exact inverse of all six changed mechanical sources. The complete
source binding reverses to #134. The default-entry reader then uses the
unchanged #134 reader to recover the older frozen 536-path source. The
historical 58-image profile retains all 120 original restore pins.

## Actual validation

The product ELF is 26,787,840 bytes, SHA-256
`d995069de6fa4f98f62a8e0412f90f7ff7cd3746706e6e0a91589569979952af`.
The private fixture ELF is 26,771,456 bytes, SHA-256
`1e25d052b8279ec1a387a8e66ed31b2dd75783d9f294c81ce9a9ea23c44f46c5`.

The default entry rebuilt all **118 direct + 8 packed** members with **zero
member reuse** in 112.463 seconds and reproduced the same product ELF. It used
the already verified original B3; this local run is not claimed as a new cold
compiler bootstrap. Normal GitHub workflows retain their original cold gates.

The installed Map and write-parameter owners, planner and slot-11 op9 owner were
actually invoked through the installed fixture. Complete outputs become the
next stage's actual inputs; the private driver only transports those stages.
The four other typed owners remain reference fixtures in this qualification.

| Domain | Complete observed result |
| --- | --- |
| Original public routes | 13 routes, 116 complete response pairs, 8 processes |
| Original root owner | All 68 queries, including prior operations, counters and capacities |
| Typed parameters | All 1,388 frozen input objects; all 196 write inputs, including 16 Map refusals and 180 admitted installed write calls |
| Call planner | All 433 objects across 24 groups, 381 actual config/root exchanges |
| Original ABI controls | All 170 typed and **27 actual** planner controls |
| Installed ABI refusals | 6 typed + 13 planner malformed frames, with valid calls before and after |
| Slot boundaries | 71, 72 and maximum u64 refused with original fatal exit 111 and no response |
| Lifetime and high bitmap | Two sessions interleaved with the existing publication route; both publication children exit 0 and are reaped |
| Pure source/resource controls | 14 source corruptions/removals, 5 trace mutations and 9 memory/process mutations rejected |

The old planner README incorrectly declared 28 controls and 13 malformed
controls. Its original producer actually emits 27 and 12. The exact already
qualified literal DATA-reader recovery in its immutable `FINAL_HANDOFF.json`
is used without editing that original package. The additional installed
trailing-byte refusal is a separately identified new control.

The complete DATA reader checks **12,350 native calls / 1,627,490,313 bytes** of
inputs, outputs, original output poison, and before/after workspaces. It uses
the original component framing and physical-control readers. The original
11-capability read-only guard rejects file writes, process execution, native
library loading, mmap and foreign reads and checks complete before/after file
identities. Seven reference builds and all 1,080 original compiler source pins
are verified as part of the read.

The exact ROG resource capture has 639 full 224-byte `HRGTR002` records plus
116 full 128-byte `HRCNAK02` records. A strict `strace -f` ledger binds the actual
root PID and its two `CLONE_VM` children. All 255 graph allocations are
explicitly unmapped; 238 guard pages and both remaps are accounted for. The
unchanged startup configuration's one 3,707,834,368-byte process-owned mapping
is released by the final `exit(0)`, not reported as an explicit `munmap`.

## Retained failures and proof boundaries

All original failed runs remain in the evidence archive:

- The first integration run used the same physical controller state directory
  for simultaneous baseline and candidate processes. The corrected run gives
  the baseline its own state directory and keeps every other config byte.
- The second run completed every semantic input but its new wrapper incorrectly
  asserted the stale planner count of 28. The original actual 27 are retained.
- The third completed every semantic and original ABI control, then the local
  cloud's `PTRACE_TRACEME` refusal prevented the resource fixture from starting.
  Its overall `FAIL` receipt is unchanged.
- The first ROG application completed successfully, but the new reader initially
  assumed all stderr records were 224 bytes. The complete failed reader output
  and original capture remain. The successor follows both actual worker PIDs,
  parses both complete record formats and distinguishes process-owned startup
  memory from graph-owned allocations.

The final source keeps ordinary reproduction drivers and strict DATA readers;
intermediate driver copies are retained only as immutable evidence. The old
124-image captures and their independent reads remain separate from the new
126-image proof. No prior 58/61/124 application qualification is relabelled as
a complete 126-image runtime qualification.

## Re-read the retained evidence

`EVIDENCE.json` identifies all archive parts, their assembled digest and the
complete logical-file/object manifest. `restore_evidence.py` checks every part,
every object, every logical file and its mode before restoring into a fresh
directory. The output preserves the `runtime-audit/binary-next` layout and
explicitly maps recorded artifact paths to the restored tree.

After restoration, run:

```sh
python3 -I -S -B tests/hia_native/binary_owners_product/guarded_integration_read.py \
  --root /absolute/restored/runtime-audit/binary-next \
  --output /absolute/new-read-proof.json
```

The default126 and both old124 independent read results, exact source inverses,
all complete process streams and the original failures are in the archive.
The public-current workflow only changes its two exact recipe SHA pins. Its
commands, budgets, normal triggers and original qualification gates remain.

## Remaining product ownership

The public handler still needs the full effect and lifetime path: authenticated
host/SSH dispatch, the qualified remote write body, exact error and output
publication, audit ownership, cancellation and cleanup. Those owners must be
integrated and qualified over the original complete domains before exposing
the public route. The existing full-native shell partition also has a separate
strict allocator mismatch between two rolling GitHub runner images; its old
failure remains a failure pending a consumer-host qualification repair.

`whole_runtime_qualified`, `public_binary_write_registered`, remote writer
effects and old-path removal remain false throughout this change.
