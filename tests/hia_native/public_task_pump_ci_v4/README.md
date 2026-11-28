# Frozen v4 task pump: complete public Bellman CI, recipe revision 2

This is an isolated qualification recipe. It does not install a production
runtime, change the main branch, replace historical evidence, or mark the full
SDK, all 136 tools, asynchronous cancellation, or the old stack as complete.

## Exact source boundaries

The package reuses 402 existing Git objects unchanged:

| Boundary | Files | Frozen identity |
| --- | ---: | --- |
| v4 graph, authors and source inventory | 223 | 81460744d5d23a6f7b354071deb8dd51890551af |
| Checked-byte worker and packed port package | 143 | 10119430f0fcb9099feaefbc524b5ff2a9445681 |
| Actual current SDK and original Bellman reference | 31 | f7ed611f9722c8d99195e555ef50b65fbc0253e4 |
| Existing stdio observer, wire reader and controls | 5 | Exact per-file Git objects in INPUTS.json |

The graph closure is
57f2aceadc6f4b4f51ad9458425f7089a65e6d4d207937245617826b2abdf7d0.
The port PACKAGE identity remains
2563acb466285cc6d9fbf3f91508b1ea0785904230263bcdea5866c30f801bb1.
The original Rust source is bound to target
d3d75c30719db966b004756f610007a7c723729e and the exact target lock subset.
The Hepta compiler is d3e2c90173cf733e42b299d0c4274df4b593a12f,
tree 8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49.

INPUTS.json provides every retained path, byte length, SHA-256 and Git blob.
PACKAGE.json covers the complete recipe, including the newly written readers.
The external workflow substitutes its package hash into ci/workflow.yml.in;
the template deliberately has no self-referential manifest hash.

## What executes

The build job compiles a fresh bootstrap and the worker from source, compiles
the packed caller from source, and executes their actual HIA packers. It then
freshly compiles all 92 direct graph members for the production entry. The
fixed FD3 journal entry and the fixed FD3/FD4 trace entry reuse only those 92
same-job members and the same fresh eight-member packed capability. Each
entry has its own actual GAS object, HIA prefix linker and HIA image packing.

There are 100 runtime HIA images in 93 physical containers. This count excludes
reference images, bootstrap generations, linkers and packers. Reusing the
same-job bootstrap is recorded; it is not called a fresh cold qualification.

A parallel job builds the unchanged reference with Rust 1.95.0 and runs its
complete original parameters, original handler, actual RMCP 3.9 public wire,
and actual SDK argument-model observations. Rust is executed only in CI.

The public job runs the unchanged 1394-record corpus: 683 tool cases per
protocol, plus the retained initialization, notification, transport and close
records. It starts two native stdio processes, with one session per process.
The reference uses one reference process and two actual SDK sessions. This
physical difference is retained in the evidence and proves no shared pool
between the two native processes.

Every native process retains its 180-second lifetime deadline and every
exchange retains 60 seconds. Every workflow job retains 15 minutes. The new
orchestration adds no outer timeout that would incorrectly claim to reap
a nested child which creates its own session.

## Evidence and independent reading

ci/read_build.py reads compiler Git objects, full compilation inputs and
outputs, every member manifest, the actual assembler records, every fixed
patch, the complete packed ELF, and all packer output/workspace bytes.
Its prefix-linker scope is the complete returned prefix; the frozen graph
builder does not retain the unused prefix-linker output or workspace arenas.

Four complete physical build clones retain real reader mutations: a compiler
output tail byte, a false fresh-member claim, a pack-workspace tail byte,
and a packed capability byte. The read-only reader rechecks each retained
clone and requires its real rejection.

The public join additionally compares every complete wire and stream, reads
the complete FD3 journal, associates actions and worker records with the
actual public exchange windows, and checks the original worker lifecycle.
The only normalized public field is native_operation_wall_seconds.
Graph hashes alone are not a public qualification.

The complete build, original and native captures are exported separately,
including failures. Export does not modify the captured input trees. Each archive contains the complete recipe source and
a full file manifest. Export rereads every tar member. Extraction verifies
the complete archive identity and every member before any qualification.
The final qualification requires all three captures from the same CI run.

After extraction, the read-only entry is:

    python3 -I -S -B ci/read_all.py \
      --package PACKAGE --build BUILD --original ORIGINAL --capture NATIVE \
      --manifest-sha256 PACKAGE_SHA256

The final reader performs no native or Rust execution and does not rewrite
its inputs or its report. The physical evidence controls and audit refusals
remain separate from semantic rows.

## Preserved failures and limits

The old 180-second/222-exchange failure remains a failure. The optimized
276-exchange failure and the 292-exchange failure remain failures. They
exposed two real mechanical publication guards: a complete business-error
result and a complete typed JSON-RPC error were produced by HIA but rejected
by the host. Frozen v4 admits the existing boolean error flag for the direct
wire kind, preserving all framing, extent and HIA-owned wire checks.

The v4 local builds and small typed-error diagnostic occurred before this
fresh CI. They are development observations, not a complete 1394 pass.
The diagnostic and large build artifacts were not fully durably archived
before the local environment became unavailable; this recipe reconstructs
from the complete Git source instead of claiming those bytes were recovered.

The retained port package has a separate known private-fixture CI failure:
READY did not imply that a child had already been reaped at an immediate
destroy call. A successor fixture fixes that assumption, but this package
does not silently substitute it or relabel the failed run. Here the same
frozen port bytes are freshly built and read; the actual public processes
must close and reap under their own complete public evidence.

The graph still advertises the frozen nine-tool catalog. The ordinary
Bellman call branch is exercised directly by this corpus. Batch's reserved
slots are not populated here, and the separate eleven-tool catalog is not
installed by this recipe.

A successful serial corpus does not qualify notification cancellation,
EOF/future-drop timing, asynchronous request generations, the entire
server router/audit layer, all configurations, or all tools. Those flags
remain false and require their own actual current-SDK comparisons.

## Preserved first fresh-CI failure

Revision 1, commit 36ad2437bfc59e8b32a8e37c41ca60f087fefb7b,
run 43908796631, built the fresh worker, packed port and all three graph
entries and passed the complete build reader. Its fourth physical reader
control then failed with PermissionError while writing a newly copied
packed ELF whose exact source mode was 0555. The original Rust job passed;
the complete public observer was not started. The failed run remains failed.

Revision 2 temporarily adds owner-write only to the newly created control
clone file, writes the declared mutation, and restores the exact mode in a
finally block. The pure reader checks every clone file mode as well as the
complete byte inventory. No graph, HIA, Rust, corpus or deadline is changed.
The byte-only readback run 43910449753 verified all 18,483 archived files
and 2,566,125,379 logical bytes without native or Rust execution.
