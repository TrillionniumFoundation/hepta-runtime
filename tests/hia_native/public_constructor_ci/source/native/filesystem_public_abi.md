# Public filesystem gateway and private observation fixture

The current candidate joins the same 58 HIA images in two executables. The
ordinary executable accepts newline-delimited JSON-RPC on standard input.
The second executable is a private qualification fixture. It installs two
independent session states and two view/cache engines in one process, with one
shared installed configuration and one shared native effect-fence hub. No
ordinary JSON request selects an engine, descriptor, scope, lease or session.

The public argv is `[executable]` for genuinely absent configuration or
`[executable, --runtime-config, absolute_config_path]`. The initial session root
comes from actual `getcwd`. Environment bytes for the existing effect-owner
fence are captured from the kernel environment, then interpreted by HIA.
Both executables use the real HIA result publisher. A publication imports its
complete prefix and body before START; it does not retain the caller's output
borrow after handoff.

## Fixed private graph

The extra engine has 33 fixed descriptors, each 64 bytes. The descriptor table
is at engine+8. An entry contains HIA entry address, workspace pointer/capacity,
bridge sequence, output pointer/capacity, last u32 return and full u64 output
extent, in that order. These addresses and indices are not public capabilities.

| Slot | Owner or boundary |
|---:|---|
| 0..20 | Existing public46 catalog, admission, view, client, params, context, Session6, policy7, canonical8, path9, Value10, config11, view engine12, workdir13..17, frontend18, protocol19, execution20 |
| 21 | Filesystem gateway |
| 22 | Filesystem typed parameters |
| 23 | Filesystem caller and private seed entry |
| 24 | Actual filesystem I/O owner and callable syscall boundary |
| 25 | Filesystem result renderer |
| 26 | Directory-move configured-root guard |
| 27 | HIA effect-fence admission/release controller |
| 28 | Actual five-image native effect-fence lifecycle |
| 29..32 | Aliases of this session's view-engine slots 6, 5, 7, 8: scope, canonical key, cache lease and cache |

The first four configuration images are the separately named span owners.
Every configuration borrow reads control+1024/+1032 and computes the current
footer as `pointer + capacity - 256`. This remains one installed instance.
The fence hub is a separate allocation and occupies no configuration control
fields. All five native fence images are physically contiguous and last in the
image table, preserving the callable boundary's precise signal admission range.

The filesystem gateway orders typed parameters, fence admission, actual session
initialization/snapshot, outer path policy, and the scoped caller. The caller
retains original preflight, rename, cache invalidation and rendering order.
The permit remains live until the caller's complete result has been copied into
the gateway's owned result storage. Request identifiers are never capabilities.

## Qualification fixture input and output

All integers below are little-endian u64. Input is `HFSFXQ02` followed by
`session, selector, payload_length` and the exact payload. Session is one of the
two already installed private engines (0 or 1). Selectors 0..32 address the
fixed internal graph; the observer and frontend selectors below exist only in
this separate executable.

Ordinary replies have a 104-byte header: `HFSFXR02` followed by twelve words:
`session, selector, return_code, output_extent, six_counter_deltas,
workspace_capacity, output_capacity`. Exactly `output_extent` bytes follow.
Returns remain their native u32 values; a resource refusal is not converted
into an original business error.

### Actual cache seeding

Selector 23 accepts the private frame `HFSSE002` followed by
`4, payload_length, 0, 0, 0`. The payload is `entry_count` and then, for each
entry, `path_length, content_length, raw_path, utf8_content`. The HIA caller
opens one actual request scope, derives actual keys, obtains the real private
cache lease and executes existing `view_cache` op 6 (`note_create`) for each
entry, then closes the scope. It returns the regular HRCFGM01 result frame.
This is a fixture seam corresponding to original scoped cache seeding; it does
not claim public filesystem execution or fabricate cache bytes in Python.
The public HFSCQ002 domain accepts only operations 1..3.

### Read-only observer

Selector 33 requires an empty payload. Its ordinary reply has code 0 and body
`HFSOBS02` followed by seven words:
`session_used, cache_used, 64, 256, 256, 0, 0`.
The 64-byte header is followed by the exact used Session bytes, exact used Cache
bytes, 64 context bytes, 256 scope bytes and 256 lease bytes. Thus the complete
extent is `640 + session_used + cache_used`. These are actual owned mappings,
copied without mutation. The observer does not export all lease records or a
live hint queue body. The context/scope/lease prefixes permit lifecycle checks;
they are not a serialization/import API.

| State prefix | Meaning |
|---|---|
| HRSWST02+8/+16 | Root length and current length; raw root starts at 64, current follows root |
| HRSWST02+24/+32/+40 | `has_current`, poisoned-lock behavior flag, initialization latch, each 0 or 1 |
| HRSWST02+48/+56 | Version 1, reserved zero |
| HVCSTA01+8/+16/+24/+32 | Version 1, used extent, entry count, poison flag |
| HVCSTA01+40/+48/+56 | Reserved zero; records at 64 are key length, value length, complete key and value |
| HRCXST01+8/+16/+24/+32/+40 | Version 1, arena size A, used end, top frame offset, scope depth; +48/+56 zero |
| HRSCST01+8/+16/+24/+32 | Version 1, generation, phase (closed/active/suspended/tombstone = 0/1/2/3), continuation |
| HRSCST01+40/+48/+56/+64 | Context slot, lease slot, cache epoch, active lease |
| HRCLST01+8/+16/+24/+32/+40/+48 | Version 1, epoch, phase, live count, last issued lease, cache slot |

An uninitialized/destroyed context prefix can be all zero. Scope bytes 72..255
and lease bytes 56..255 retain the existing owner's private operation and
continuation scratch. Preserve and bind their complete bytes, but do not infer
unrelated public fields from them. Lease records reside in the owner's arena
after its fixed workspace region and are not included in this 256-byte prefix.

### Same-frontend private requests

Selector 34 takes one complete raw JSON message, without requiring a trailing
newline. It executes the same HIA frontend and real publisher as production.
Its 96-byte header is `HFSJPR02` followed by eleven words:
`session, mode, closed, six_counter_deltas, 0, 0`.
Mode 0 is silent, 1 is a raw response, 2 is a published response and 3 reports an
already closed private connection. Modes 1/2 are followed by the complete JSON
response line and its LF. Modes 0/3 have no response bytes. A mode-3 fixture
record is not a BrokenPipe observation. Public transport closure must be
observed separately by writing to the ordinary executable's actual pipe.

## Counters and complete receipt streams

The six deltas cover engine fields 128..168:

1. Instrumented HIA invocations: generic extra entries, I/O wrapper entries,
   and actual native fence child calls accumulated by that wrapper.
2. Successful workspace growth recorded by this engine and its I/O wrappers.
3. Successful output growth recorded by those boundaries.
4. New controller child dispatches, before invoking the selected child.
5. Delivery-only retries that consume a retained child result.
6. Short parent delivery windows that return the private DELIVERY marker.

These counters do not claim a complete count of every nested view/config HIA
call or every process syscall. In particular, the sixth is a short-delivery
count, not successful-redelivery count. The same logical child result can
survive multiple growth requests without a new dispatch. Native fence calls
are additionally accumulated at engine+240 and effects at engine+248.

Production leaves engine+80 zero. The fixture sets it to 3, meaning fd 2 plus
one. Its stderr is a concatenation of fixed binary receipts, with no inserted
JSON framing. No request can set that sink. Relevant records are:

| Magic | Bytes | Fields after magic |
|---|---:|---|
| HRGTR002 | 224 | Trace sequence, extra slot, event, captured rax, workspace cap, output cap, raw workspace word at 8, raw word at 16, descriptor extent; exact workspace[256:368] (112 bytes), exact output[0:32] |
| HFSPCL02 | 80 | Filesystem f0 ordinal, return code, phase, generation, effect sequence, current input length, output cap, workspace cap, logical FD mask |
| HFSPAK02 | 192 | Raw syscall return (two's complement for errno), f0 ordinal, phase, three physical FDs after completion, logical FD mask; exact 128-byte HFS PFX effect/action record at workspace[512:640] |
| HRCNAK02 | 128 | Canonical effect receipt described by the source-owned canonical boundary; exact sixteen-word record retained |
| HWDIOAK2 | 160 | Sequence, generation, raw phase word, effect selector and four argument words, raw syscall return, value/errno/completion words, private physical FD/state words, repeated sequence and reserved zero |
| HVRDACK1 | 128 | Seven words copied from the view reader's workspace[520:576], its physical FD, four completion words from workspace[592:624], stored sequence, input length and repeated sequence |
| HFLKEYFX | 128 | The complete view-key effect/action record from workspace[512:640], after the actual ACK at workspace+608 has been written |

HRGTR002 event 1 follows an instrumented call, 2 follows successful growth,
3 precedes a new child dispatch and 4 follows an actual completion or short
delivery marker. Its raw workspace words are only phase/sequence for owners
whose own ABI defines them that way; for leaves they have other meanings.
The 112-byte snapshot is not required to be an action frame on every leaf.
This fixture's private extra-engine sink also enables its associated view
engine's existing trace flag at view-engine+96, so actual view-key and view-read
effects produce the two records above. Ordinary production creation leaves
both switches disabled. Neither switch is selected by JSON input. Configuration
growth receipts require the separate config control+1144 switch, which this
fixture does not set. Native fence child calls are counted as described above;
this fixture does not emit a separate complete per-effect native-fence stream.

The three filesystem I/O descriptor slots are physical FDs kept by that owner,
with -1 meaning closed. Their original maximum of three is per owner. The
combined process can also hold configuration locks, canonical path descriptors
and real fence permits; there is no claim that total process FDs are at most
three. Callback completion writes the real HIA ACK fields before the next f0.

The current capture proves synchronous serialized calls through this actual
graph. HTTP scheduling, unrelated public methods, unconstrained regex resource
domains and the whole runtime are separate obligations. A successful finite
fixture is not a new request-count quota or proof of all asynchronous races.
