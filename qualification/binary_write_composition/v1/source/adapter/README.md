# Isolated HIA binary write request adapter

This source implements a pure HIA continuation between the already installed
binary call planner and the independently implemented parent owner. It does not
register a public tool, perform a file effect or complete host/audit/SSH/lifecycle
integration. See `ABI.md` for the exact private contract.

The adapter and unchanged planner both use the existing three-buffer entry.
Start suspends with a complete fixed planner request. A qualification carrier
calls only the byte-identical actual HIA planner, returns its whole result and
lets HIA compare the complete prior ready frame, including every JSON byte.
HIA then constructs `HBPWQ001`, keeping version presence, raw UTF-8/NUL, Base64
and path bytes intact. The adapter never receives or chooses a parent FD.

## Frozen scope

`inputs/INPUTS.json.xz` retains the complete old 433-case / 24-group planner
domain, all 196 write typed inputs from the old 1,388-case typed domain, and all
256 parent interface input records. Extraction verified every one of the old
12,350 native records and 1,627,490,313 logical bytes before deriving the inputs.
The old original captures and their published #135 archive remain authoritative
historical evidence. This isolated suite does not rerun their Rust oracle.

There are 59 old write planner inputs and 19 actual ready write results. Earlier
typed, caller and root failures retain their original output and never enter the
adapter. The parent interface projection is a pure byte test: `{R}` becomes the
literal `/binary-parent-interface`, host is `parent-interface-fixture`, and a
declared successful private root feedback supplies the exact root string. It
does not execute the parent's filesystem fault plans, FD actor, resource controls
or writes. Its two missing-version cases remain typed String errors. No result
from this projection requalifies the parent's 256 effect domain or old body101.

All 53 private controls are named in `CONTROL_DOMAIN.json`: 50 physical refusals,
two mismatches involving the actual unchanged child, and a 16-event lifecycle
case. The source rejects stale/duplicate/busy continuations, preserves full
workspace on growth/refusal, and records complete mismatching child bytes.
The DATA reader independently reconstructs every named refusal's complete input,
initial capacities, workspace and return code. It also binds all 16 lifecycle
events to exact ordered requests, generation numbers, retained contexts, actual
growth records and complete output bytes. The earlier capture is retained as a
reader regression fixture; it supplies no native execution credit for this source.

## Actual qualification commands

Freeze the complete source with `scripts/freeze_source.py` after review. Builds
and captures must use fresh nonexistent output directories. The exact compiler
is `d3e2c90173cf733e42b299d0c4274df4b593a12f`, with the existing development B3
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
No new compiler cold qualification is claimed by these commands.

```sh
/usr/bin/python3 -I -S -B scripts/build_images.py \
  --hepta /absolute/exact/compiler-source \
  --retained-bootstrap /absolute/exact/bootstrap --output /absolute/run/images
/usr/bin/python3 -I -S -B scripts/run_capture.py \
  --images /absolute/run/images --output /absolute/run/capture
```

Each of the 24 complete original planner groups retains its 60-second process
bound. The complete typed subset, complete interface projection and all controls
each have the same 60-second bound, with 5-second cleanup and 1,800 seconds for
the complete capture. A timeout is retained HOLD; the reader requires all 27
natural successful processes and every attributed invocation.

Independently obtain SHA256 of `SOURCE_MANIFEST.json` and actual `capture/RUN.json`
before supplying them to the DATA-only reader:

```sh
/usr/bin/python3 -I -S -B scripts/read_capture.py \
  --images /absolute/run/images --capture /absolute/run/capture \
  --source-sha256 ACTUAL_SOURCE_SHA --capture-sha256 ACTUAL_RUN_SHA \
  --output /absolute/run/READBACK.json
```

The reader checks all 1,080 compiler source inputs, the real compiler requests
and complete output receipts, all four native images, source identities, full
process streams, every native input/output/workspace byte and all parent packets.
Fresh planner and typed image bytes must also equal their installed #135 images.
New local proof, normal GitHub CI and the prior owner qualifications are separate
scopes. `public_binary_write_registered`, `production_carrier_installed`,
`host_audit_ssh_lifecycle_qualified` and `whole_runtime_replaced` remain false.
