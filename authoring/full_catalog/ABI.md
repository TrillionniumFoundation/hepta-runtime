# Complete raw-declaration catalog capability

This capability consumes the complete original 136 Tool declarations at runtime.
The original HIA catalog policy, serde Value owner, and SDK catalog constructor
execute in order. The declaration array is data; no expected result wire is
embedded as the implementation of the configured list operation.

## External interface

The Linux x86-64 callable has the existing three-buffer ABI: source pointer and
length, independent output pointer and capacity, independent mutable workspace
pointer and capacity. Its position-independent flat image starts at offset zero.
The code and declaration data are mapped read-only/executable; per-call state
belongs to the caller's workspace and one temporary request mapping.

Configured list requests have exactly 40 bytes:

| Offset | u64 field |
| --- | --- |
| 0 | Eight bytes HRMCD002 |
| 8 | Operation 7 |
| 16 | Modern typed result policy, 0 or 1 |
| 24 | Configuration value described below |
| 32 | Explicit request profile |

Profile 11 preserves the existing caller interface: configuration is runtime
presence 0 or 1. Profile 136 accepts the original complete policy flags: 0 or an
odd value from 1 through 15. Bit 0 is runtime configuration, bit 1 is HIA
configuration, bit 2 is REA profiles, and bit 3 is weight workers. Selection of
trusted configuration remains a caller responsibility.

The current public caller's profile 11 therefore uses original policy flags
0 or 1. Other original configurations are supported through explicit profile
136; this does not itself install a public configuration selector or any Tool
handler.

Success returns 32 and writes the existing HRCATR02 descriptor:

| Offset | Field |
| --- | --- |
| 0 | Eight bytes HRCATR02 |
| 8 | Status zero |
| 16 | Complete payload byte length |
| 24 | Zero |
| 32 | Complete comma-result suffix, including its final response brace |

The payload is exactly comma + quoted result key + colon + the actual SDK
typed JSON object + the closing JSON-RPC response brace. It contains the full
original Tool objects, schemas, order, titles, descriptions, resultType field,
and applicable modern cache fields.

Growth returns 0xffffffd0 with HGRWS002, kind 1 for workspace or kind 2 for
output, the exact required capacity at offset 16, and zero at offset 24.
Workspace requires 104861696 bytes. Output growth reports 32 plus the actual
complete suffix length. Workspace is scratch: computing exact output growth can
change it. Initial workspace growth leaves it untouched. Output beyond the
32-byte growth descriptor or complete success extent is unchanged.

Malformed configured-list requests return 0xffffffff. An output shorter than
32 bytes returns 0xfffffffe before writing. All other original requests pass
unchanged to the retained catalog image, preserving its complete return, output,
workspace, initialization, errors and older private operations.

## Runtime composition

The five runtime images are:

1. New HIA pipeline owner.
2. Original HIA catalog policy.
3. Original HIA serde JSON Value owner.
4. Original HIA SDK catalog constructor.
5. Retained HIA catalog for the other original requests.

The pipeline starts from the exact 776697-byte declaration array whose SHA256 is
d150e2a180b9faaccb8f10414cbc83c9b3278efa39802c2e65123d0056c125fd.
It supplies all 136 declarations to HCATCQ01 operation 1, then uses HSJVAL01
operation 1 and HRRSP001 operation 4. Each complete child header and extent is
validated before the next call or publication.

The complete ordinary and modern visibility counts are:

| Original flags | Visible Tools in each modern class |
| --- | ---: |
| 0 | 10 |
| 1 | 113 |
| 3 | 124 |
| 5 | 118 |
| 7 | 129 |
| 9 | 119 |
| 11 | 130 |
| 13 | 124 |
| 15 | 135 |

The input domain always has 136 declarations. These counts result from the
original visibility policy and are not a replacement for that input domain.

The workspace contains a 4096-byte control area, two separate 2 MiB frame
regions, and a separate 96 MiB child workspace. Policy and Value receive their
original 32 MiB workspace capacities; SDK receives its original 96 MiB capacity.
The boundary permits only the fixed three image targets and disjoint fixed
regions. HIA owns all selection, frame construction, validation and JSON bytes.

## Mechanical boundary

The assembly boundary wraps the original query in a private 32-byte HFCAPQ01
transport header. It always begins with stage zero, copies the immutable
declarations only when the HIA owner requests them, then performs the bounded
image calls requested by that owner. The original query remains independent of
mutable child arenas. Private continuation stages cannot be supplied directly
through the external public source buffer.

A per-invocation mapping is released on every return. There is no shared mutable
catalog state, runtime Python, Rust, libc call, JSON parser or policy fallback in
this boundary. Linux mmap and munmap are the only boundary system calls.

The author imports only the retained checked load/get/put, growth and descriptor
functions. Complete inverse AST proofs bind those imports. The new owner has
seven functions and 508 operations. The three original policy-pipeline sources
and the retained catalog source are unchanged.

## Build and qualification

Run scripts/hia_native_full_catalog.py with explicit source, Hepta, qualified
bootstrap and fresh output directories. It reproduces the HIA author; checks
the complete 29-file original source inventory; performs seven actual HIA
compilations, including the HIA ELF linker and image packer; and verifies the
complete packed result. The flat capability is the exact suffix at offset 256
of the actual HIA-packed container. All relative calls, original image spans
and declaration bytes remain intact. Assembly has no outstanding relocations.

The dedicated test loader admits the custom five-image build record and sealed
composite image. It does not label this composite as one compiler-produced
native module.

With HIA_FULL_CATALOG_BUILD and HIA_FULL_CATALOG_EVIDENCE set to the build and a
fresh evidence directory, run:

    python3 -I -B tests/hia_native/test_full_catalog_capability.py

The six methods compare all 18 complete original policy ABI shapes against
separately executed original HIA policy/Value/SDK images, compare both retained
actual flags-1 ordinary/modern handler wires, compare 187 retained-request
triples, and check malformed requests, precise capacity edges, native child
frame admission, and independent simultaneous calls. Every call retains its
complete input, output and workspace with digest-bound lossless records.

This component qualification does not certify the remaining public Tool
handlers, the complete asynchronous runtime, a new Rust process run, production
activation, or removal of the old runtime stack. The original 216 Rust handler
observations are not relabelled as newly executed.
