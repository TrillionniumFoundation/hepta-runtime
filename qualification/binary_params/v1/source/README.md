# HIA binary tool parameter owners

This frozen source contains five HIA typed owners for FileInfoParams,
BinaryReadParams, BinaryWriteParams, BinaryUploadParams and InodePatchParams.
The original declarations and first four original parameter tests are retained
byte for byte from hepta-runtime d3d75c30719db966b004756f610007a7c723729e.

The production-language source is HIA. Python is limited to source authorship,
build orchestration, actual ABI capture and evidence reading. Rust is retained
only as the exact original typed comparison oracle. These fixtures do not install
a public route, execute a binary handler body or close the full runtime.

## Frozen domain and actual comparison

DOMAIN.json binds 1,388 input-only cases, split 120 / 240 / 196 / 410 / 422,
and 170 private ABI controls. Native capture invokes the fresh HIA Map owner
followed by the corresponding fresh typed owner. It never reads Rust results.
The separate original process applies serde_json to the exact original types.
The reader compares every admitted canonical object and complete typed result,
including the complete original typed error text and all u64 bits.

All six modules are compiled from source through the pinned Hepta B1/B2/B3
fixed point. Complete compiler source, build input/output, generated images,
original crate archives and extracted registry files remain in the evidence.
Every native entry retains complete input, before/after workspace and initialized
before/after output buffers. Growth retains the previous workspace bytes.

## Bounded CI qualification

scripts/run_gate.py performs source preflight, fresh producers, pure admission,
six complete physical evidence refusals, two complete relocations and the final
pure comparison. Ordinary processes have a 60-second limit, builds 900 seconds,
and pure readers 180 seconds. The native case domain is not reduced after a
failure. Process status, full stdout/stderr and actual limits remain retained.

Physical variants are complete ordinary file trees. Immutable unchanged bytes
share regular-file links during setup; each mutation uses atomic replacement.
Setup link-count and ctime changes are declared. Every reader starts after setup
and proves that all its evidence bytes and metadata stayed unchanged, while
eleven actual denied capability probes prevent writes, subprocesses, mmap,
ctypes and foreign reads.

scripts/export.py preserves all files and directories, full file bytes and
modes in a lossless content-addressed archive. It rereads every packed object.
scripts/archive_read.py restores the complete logical set, checks all retained
process streams and guard proofs, and runs the pure reader in a new process.
It does not execute HIA, Rust or any original effect. Failed stages are retained
and are never reported as passing comparisons.

## Scope

This source qualifies typed deserialization only. Reading-root authority,
configured host selection, path semantics, actual binary file operations, SDK
routing, session/async behavior and public registration require their own actual
caller comparisons before these modules can replace public handlers.
See ABI.md for the fixed private wire format.
