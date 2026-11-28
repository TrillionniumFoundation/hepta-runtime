# HIA static ELF linker (explicit Linux x86-64 profile)

The checked-in `elf_static_linker.hepta` performs object parsing, exact-name
strong/weak symbol resolution, section layout, relocation validation/application
and ET_EXEC emission. `native_filter_packer.hepta` emits its standalone syscall
CLI. Runtime requires neither Python, ld, libc nor a dynamic interpreter. The
host build driver still owns files, completed-cold-compiler admission and receipts.
This is not a default production linker switch or whole-toolchain retirement.

## Wire and application limits

Input is little-endian `HIALNK01`, u64 object count, u64 entry-name length, u64
reserved zero, exact entry bytes, then one u64 byte length plus ET_REL bytes for
each object. There are no implicit trailing bytes. Entry is an explicitly chosen
zero-argument scalar C-ABI function; ELF symbol tables do not encode a checked
high-level function signature. The caller must supply that ABI. The low byte of
its scalar return is the process exit status.

Separate application profile: input/output8MiB, private workspace16MiB,
64objects/4096sections/32768symbols/8192globaldefinitions/32768relocations,
4096byte symbol names and at most4096byte power-of-two section alignment. These
are not raised compiler ceilings; the native compiler retains its original1MiB
source/output/workspace and all existing function/SSA/block/node limits.
No native application output is written until all admission/resolution/relocation
checks succeed. Bad input, unsupported features, unresolved referenced strong
symbols, duplicate strong definitions and overlapping/overflowed fixups return
INVALID; insufficient caller output/workspace returns NO_SPACE. CLI invalid/
space/I/O/usage statuses are2/3/4/64. Partial external writes are not transactional
publication; EINTR is retried and a later I/O failure preserves the actual prefix.

## Native scope

- ELF64 little-endian x86-64 ET_REL, one ordinary SYMTAB per object.
- Allocated PROGBITS/NOBITS with read/execute or read/write layout, never W+X;
  zero initialization of BSS; independent private symbols across objects.
- Exact byte names, local/global/weak binding, absolute symbols, defined-strong
  over weak, deterministic first weak definition and unresolved weak address0.
- RELA NONE/64/PC32/PLT32/32/32S, actual target extent, symbol, overlap and
  signed/unsigned narrowing checks. Static PC/PLT references resolve directly.
- GNU `FEATURE_1_AND` CET bits IBT/SHSTK are understood: the emitted startup has
  neither feature, so the intersection is zero, as with ld and that startup.
  Other allocated notes/needed or unknown properties are refused, not dropped.
- RX and RW load segments, nonexecuting RW stack, no interpreter/dynamic loader.

TLS, COMMON/COMDAT, merging/string-section semantics, dynamic shared-object/PLT/
GOT linking, other relocation types/targets, libc allocation and the full module/
package/build graph are still open. Unsupported objects are not relabeled valid.
The linker preserves admitted machine code; it is not a machine-code verifier.

## Verification boundary

Independent Core execution and a real foreign ld control precede native B0.
Fresh B1/B2 compile the linker and packer. Complete output is compared with Core;
real kernel execution covers data/BSS, nonzero addends, absolute relocations,
weak resolution, two independently HIA-emitted objects, private-name collisions,
typed C callers and pure HIA entry selection. Negative input controls require
unchanged output. The standalone CLI is also observed through real syscall traces
and injected first read/write EINTR, not host payload parsing or mock linking.
Clean-source/cold/full/remote/platform gates remain separate until recorded.
