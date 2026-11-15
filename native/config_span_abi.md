# Configuration span owners

These four HIA images extend configuration file loading, JSON decoding,
validation, and installed-owner storage across the old 8 MiB / 32 MiB carrier
limits. They preserve the existing semantic wire protocols and introduce an
explicit request to grow a private borrowed buffer. Linux allocation remains a
mechanical boundary; configuration parsing, validation, state transitions,
completion delivery, and rendering execute in the HIA images.

## Separate functional sources

The final functional names are `config_directory_owner_span.hepta`,
`config_fs_span.hepta`, `config_json_span.hepta`, and
`config_validation_span.hepta`. Their bytes are identical to the four sources
compiled and exercised in the frozen qualification source. The accompanying
`config_mcp_grow_adapter.S` is the complete qualified mechanical adapter.

The old sources and `config_mcp_adapter.S` retain their existing names and
qualification. Existing fixed-carrier tests, profiles, and readers must keep
their old pins until their callers have migrated. In particular, a passing old
15-suite configuration gate does not qualify this new ABI, and the new span
gate does not change an old carrier's refusal contract.

## Growth record

All fields below are unsigned little-endian 64-bit integers. The ordinary
borrowed-bytes entry point and its u32 return channel remain unchanged.

On return `0xffffffd0`, the first 32 output bytes contain:

| Offset | Meaning |
| --- | --- |
| 0 | ASCII `HGRWS002` |
| 8 | Kind: 1 workspace, 2 output, 3 resource/arithmetic refusal |
| 16 | Required full extent for kind 1 or 2; zero for kind 3 |
| 24 | Zero |

An output borrow shorter than 32 bytes returns the retained capacity refusal
without writing either buffer. For kind 1 or 2, grow only the indicated owned
mapping, preserve its entire previous contents, and retry the same logical
invocation. Input bytes, pending effect/completion, and child result custody
must survive the retry. A kind-3 refusal is not permission to clear state or
repeat a completed external effect.

The qualified Linux boundary uses anonymous read/write mmap for a first
allocation and mremap with MAYMOVE thereafter. It doubles capacity from at
least one page until the requested extent fits, with checked arithmetic and
real syscall failures. It publishes the new pointer/capacity only after a
successful syscall. It performs no semantic fallback and no fixed cumulative
configuration-file quota check.

Successful replies retain their old wire layouts and return conventions.
This qualification covers the explicit inputs recorded by the final evidence,
including the formerly failing wide roots. It does not establish an unlimited
u32 result channel or compatibility for every unrelated fixed-capacity caller.

## Single installed configuration instance

The adapter control allocation owns six independent pointer/capacity pairs:

| Control offsets | Owned mapping |
| --- | --- |
| 1024 / 1032 | The unique installed configuration owner |
| 1040 / 1048 | Configuration filesystem state and read snapshot |
| 1056 / 1064 | JSON state |
| 1072 / 1080 | Retained child output |
| 1088 / 1096 | Root output |
| 1104 / 1112 | Validation state |

Offsets 1120 and 1128 hold the completion-delivery flag and retained child
extent. Offset 1144 controls private growth receipts; production leaves it
zero. Offset 1152 is the receipt sequence. The whole range 1024..1159 is
reserved to this boundary, including currently unused words. A shared fence
manager must use a separate hub.

The old fixed `ROOT_WORK` address is not a second instance of the new owner.
Every consuming engine's configuration slot must borrow the current pointer
and capacity from control+1024/+1032. Before a configuration op 7/8 invocation,
calculate its footer from `owner_pointer + owner_capacity - 256`; kind 1 is
stored at footer+120. Do not use the old fixed capacity or fixed footer offset,
clone the owner, reinstall configuration per session, or clear the installed
state after a read. Re-read the descriptor when a continuation can grow it.

Startup uses the same HIA installation path and the same lock lease as before.
An absent configuration uses the original kind-4 initialization; it is not an
installed empty roots list. A configured startup uses kind 0. Shutdown invokes
the original kind-2 release on the same owner before releasing mappings.
Changing the configuration file while installed does not reload it. Moving the
state directory does not transfer its retained inode-bound locks to a newly
created directory at the same path.

The registered tests exercise op 7 through the actual shared installed
instance. Remote op 8 queries borrow their input directly and compute the full
result extent before writing a body. An insufficient output span requests
kind-2 growth without scaling the persistent configuration workspace to the
input path length. The existing u32 result-channel refusal remains explicit.
Public op 8 caller integration remains a separate obligation; private owner
regressions do not qualify unexecuted public configuration routes.

## Owner relocation and completion delivery

The owner has a 1 MiB header and seven regions, each of quantum C. C is a power
of two of at least 1 MiB. The required workspace extent is `1048832 + 7*C`,
including the movable 256-byte footer. Initial minimum workspace is 8388864
bytes. The mechanical adapter rounds it to 16 MiB.

The HIA owner records a pending old workspace extent at offset 65008 and the
required extent at 65016, then moves the old footer itself when retried with a
larger borrow. It relocates region offsets and retained action spans inside
HIA. The boundary must preserve the old bytes and must not independently
relocate these records.

A completed child result is retained in the separate child-output mapping.
The boundary marks the existing action completed and re-enters the owner with
those exact bytes. If the owner requests growth before accepting them, keep
the completion and deliver it again; do not call the child again. Once HIA
accepts them, it copies them to its own current region and clears the delivery
marker. Cached final output has a distinct HIA path, so growing the root output
does not repeat parsing, installation, filesystem effects, or lock acquisition.

## Filesystem and validation continuation

The filesystem child retains its 64-byte `HRCFSR01` header; the snapshot length
is at offset 40. Configuration reads use 64 KiB windows in a growing mapping.
The 64 KiB window is not a total-size quota. A read/open completion stays
pending while workspace growth is requested. The child preflights effect
sequence overflow before consuming the completion or mutating pending state.
Output growth after close copies the retained snapshot without another read.

JSON keeps the `HRCFGJ01` input and existing typed projections. Validation
keeps its existing child-call protocol and completion sequence. A delivery-only
retry must not rerun the regex child. Retained legacy typed failures are
compared in their native return-code domain; these tests do not claim that an
unowned Rust diagnostic string has become a new HIA diagnostic contract.

## Mechanical trace and qualified scope

Only the private fixture enables 80-byte `HRCGRO02` records containing
sequence, descriptor, selector, old extent, requested extent, resulting
extent, raw syscall return, old pointer, and new pointer. The strict reader
binds them to actual mremap records. A failed allocation preserves pointer and
capacity. Lease capture also binds complete stderr bytes to actual write(2)
payloads. Guard strace used `-s 0` and therefore has truncated payload strings;
complete guard stdin/stdout/stderr are retained and checked separately.

The completed gate proves 81 guard cases against unchanged fixed-Rust-1.95
observations, 6491 typed plus 2063 semantic cases, 60 full-buffer private state
calls, seven real lease/resource ELF processes, 45 physical evidence refusals,
and two complete read-only relocations. Private synthetic completions are not
counted as real filesystem effects. The 19-image build reused a verified d3
bootstrap; it is not a new cold-bootstrap qualification.

The legacy public config MCP slot 5 still owns a distinct fixed output borrow.
The adapter explicitly refuses its unsupported output-growth path. The final
public FS graph must be rebuilt with these span owners and the same installed
configuration binding. The frozen public46 graph, unrelated identity/path
carriers, remote routes, and whole-runtime closure are not replaced by this
handoff.
