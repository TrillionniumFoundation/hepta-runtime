# Closed native HIA composition

This Linux x86-64 LP64 boundary composes immutable, manifest-pinned HIA flat
images with the existing three-buffer ABI. HIA owns application parsing,
authorization decisions, child selection, response serialization and IO state.
The fixed adapter translates admitted spans, calls fixed native entries,
forwards the one IO owner's typed effects and transports newline frames.
The emitted static executable requires the Linux kernel. It contains no Python
or Rust semantic dispatcher, interpreter, dynamic linker or libc dependency.

The supported runtime profile is explicit:

```
native-local-read.elf --local-read-profile /administrator/selected/root
```

The complete argument vector must match that shape. A missing or extra argument
returns 64. The root comes only from startup argv, is copied into a private
read-only mapping, and never comes from a client JSON field. The local service
uses the fixed name `native-local`; this does not reinterpret an SSH host alias
or port the original configuration loader. Root descriptor custody and its
rename/replacement semantics remain as documented in the IO owner.

## Embedded modules and memory

The HIA packer validates between 1 and 16 modules, with at most 1 MiB per flat
image and 8 MiB across its complete input/output envelope. Those are component
and application capacities respectively; no upstream compiler limit is widened.
The root module has 8 MiB input/output capacities. Each module has a fixed
private workspace of at most 32 MiB. Workspaces persist between requests and
are disjoint from one another, transport buffers and the administrator input.
Guard pages follow the transport buffers and each private workspace. Code is
in an RX ELF segment; data and stack are writable and non-executable.

Every 128-byte RX table entry contains code offset/length, input/output/workspace
capacities, workspace offset, flags, call mask and exact source/image SHA256
values. The build manifest also pins the compiler and all component manifests.
No request can supply a code address, load a module, alter a table or select a
child workspace. Native HIA modules are trusted compiled code; this boundary
does not claim an isolation mechanism for arbitrary hostile machine code.

| ID in the local service | Owner | Flag | Allowed callees |
|---|---|---|---|
| 0 | MCP controller | 1: continuation | 1, 2, 3, 4 |
| 1 | Policy | 0: leaf | None |
| 2 | Binary codecs | 0: leaf | None |
| 3 | Descriptor IO | 2: IO leaf | Typed OS effects only |
| 4 | Stat-version codec | 0: leaf | None |

Only ID 3 may carry the IO flag, and the production builder requires its source
to equal the selected IO owner. Generic qualification fixtures use different
fixed tables without obtaining that flag. The maximum active call depth is 8,
including the root. An already active module cannot recur. At most 8192 native
entries/effect resumptions are admitted for one root frame. This count bounds
continuation churn; it does not add an instruction meter inside a HIA function.

## Call continuation

Only flag-1 modules reserve the last 256 bytes of their workspace for a call
record. A module returns `0xffffffe0` to request one child invocation. All fields
are little-endian u64 and relative to `B = workspace_length - 256`.

| Offset | Field |
|---|---|
| 0 | ASCII `HIACAL01` |
| 8 | Sequence, starting at 1 and increasing across the module's lifetime |
| 16 | Fixed target module ID |
| 24, 32, 40 | Input region, offset, length |
| 48, 56, 64 | Output region, offset, capacity |
| 72 | Reserved zero |
| 80 | Child's complete u32 result, written on completion |
| 88 | Completed sequence, initially zero |
| 96 | Completed flag, initially zero; adapter writes 1 |
| 104 | Bridge admission status, zero on an executed child |
| 120 | Invocation kind, adapter-owned |
| 128 | Current module ID, adapter-owned |
| 136 | Current zero-based active depth, adapter-owned |

Input regions are 0=current input, 1=current output, 2=own workspace,
3=immutable administrator root. Output regions are 1=current output and
2=own workspace. Admission checks offsets by subtraction before pointer
arithmetic, enforces the target capacities, requires disjoint nonempty input
and output spans and excludes the caller's footer from output. The child's
workspace is fixed by the table and cannot overlap either borrowed span.

A well-formed sequence is consumed even when child admission fails. No child
runs in that case: the adapter writes result `0xffffffff`, matching completion
sequence, flag 1 and one status: 1=target/mask, 2=depth/active recursion,
3=region/span/capacity/footer bound, 4=span overlap. Malformed magic, sequence,
reserved word or pending completion fields terminate the process. Callers must
check the acknowledgement and status before using a child result.

On an admitted child return, all domain results in `0xffff0000..0xffffffff`
are preserved for the parent except the two reserved continuation codes. A
normal result must fit the child's output capacity. The adapter checks the
full native 64-bit return for dirty upper bits. IO yields are admitted only
from flag 2; call yields only from flag 1. The IO workspace has no generic
footer: writing one there would overwrite its file-data buffer.

## Startup, frames and shutdown

The root first receives the exact administrator root as input and invocation
kind 0. It must return zero after initializing children. Each stdin line then
has kind 1; the terminating LF is excluded from the input. A blank line remains
a kind-1 empty input. EOF invokes kind 2 after processing a final nonempty
unterminated line. Child continuation modules receive kind 3. The root's kind
is restored across every child resumption.

The input ceiling is 8 MiB excluding LF. An exactly full line is accepted only
if the next byte is LF or EOF; another byte fails closed. A positive root result
is written completely followed by LF; zero produces no bytes. Reads/writes
handle partial transfers and EINTR. SIGPIPE is ignored so broken output exits
74. The IO owner closes request handles before responses and its root on EOF;
the adapter closes all still-tracked handles on every fatal exit.

Exit codes are 0=clean shutdown, 2=invalid frame/continuation/native contract,
3=capacity refusal, 64=invalid command line, 74=transport/setup IO failure.

## Reused upstream facilities

Hepta's in-process native continuation and source-owned ELF packer establish
the same fixed-native-call pattern. Its `HIALOW01` continuation uses the object
effect ABI and 1 MiB unit workspaces, while the existing runtime modules use
bounded borrowed-byte inputs and 32 MiB workspaces. Its static ET_REL linker
accepts scalar object entries; these components are three-buffer flat images.
This application therefore supplies its own closed borrowed-byte table and
HIA packer. It does not claim qualification inherited from either distinct ABI.

The compiler pin is `d3e2c90173cf733e42b299d0c4274df4b593a12f`. The native build
and full upstream cold qualification remain separate evidence. A successful
local read profile does not replace unsupported host/configuration, remote,
write, execution, HTTP, or other runtime owners.
