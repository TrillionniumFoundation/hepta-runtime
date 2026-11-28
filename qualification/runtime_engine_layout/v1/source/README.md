# Native descriptor ownership storage qualification

This source tree qualifies only the fixed engine storage layout and ownership
lifetime boundary. It does not qualify a new public tool or claim that the
runtime has been replaced.

The production reference is pinned in REFERENCE.json. The existing 59-slot
engine is compiled unchanged. The candidate changes exactly six variable-index
bit operations, the descriptor-table placement expression and the associated
fixed layout constants. The first work and output ownership words remain at
engine offsets 64 and 72. The unchanged task handoff, workdir and filesystem
consumers continue to use those low words. Slots from 64 onward use two
independent arrays after the descriptor table. The continuation area, table,
high ownership arrays and final guard page never overlap.

The graph count is a build-time constant. It is not selected by public input.
layout.py derives storage from that count and rejects only a missing required
fixed graph or an unrepresentable native displacement. It adds no application
input quota. Default 59-slot and 64-slot storage preserve the existing offsets
and 16 KiB engine extent. A larger graph can relocate the table and enlarge the
engine while consumers continue to follow the table pointer at offset 8.

## Frozen domain

CASES.json contains input actions only: 57 scenarios and 1,182 actions over the
unchanged 59-slot engine and 18 candidate graph sizes from 59 to 1,025 slots.
No old engine is invoked beyond its 59-slot graph. The domain covers every
declared ownership-word boundary, the continuation/table relocation boundary,
owned and shared-borrowed buffers, repeated calls, exact slot18 detach/restore,
the actual fixed slot15/24 allocation boundaries, busy-continuation refusal,
invalid/null-entry refusal and real failed munmap operations followed by repair.

The only HIA leaf is an actual compiled 64-byte copy component. GNU assembly
retains the complete real engine, allocator and fixed consumers. The authority
create/release and optional handoff trace callbacks are explicitly inert private
fixture boundaries; their separate semantics are outside this qualification.
Every other unresolved capability is a terminating trap. No application body
receives a successful host replacement.

## Execution and evidence

build_native.py verifies all 1,080 pinned compiler source files, builds fresh
B1/B2/B3 fixed-point compiler generations and compiles the HIA leaf. This is
development fixed-point evidence, not a claim to replace the compiler's separate
cold qualification. The driver retains every source, compiler generation,
assembler input, object, linked image, symbol output and complete process stream.

native_runner.py calls the actual native entry points. It captures both sides
of every declared action, all owned and borrowed buffer bytes, source/node/table
canary bytes, the complete engine and control mappings, executable image bytes,
and the kernel mapping permissions of inaccessible guard pages. Shared borrows
are released only by the fixture after the engine is gone. Failed unmapping is
performed by the actual native syscall; the recorded descriptor is repaired only
by the next explicit input action.

reader.py is a pure reader. It validates all captured physical bytes and map
lifetimes and compares the unchanged and candidate 59-slot runs after normalizing
only verified native pointer locations. Four separately retained physical
mutations must be refused. Two full relocated copies must be admitted under the
unchanged read-only guard. The independent archive reader checks every retained
object and logical file, including all rejected control evidence, and admits a
fresh complete reconstruction without native or Rust replay.

Native execution is limited to 60 seconds, readers to 180 seconds and the build
to 900 seconds. The CI job remains limited to 15 minutes. Every unsuccessful
stage and its complete bytes are exported. Unknown runs are never replayed.
This source is frozen in Git before native execution. Main-branch integration
and public-entry qualification remain separate work.
