# Private native operation crypto scope

`operation_scope.hepta` owns one serial private instance of the original
`ResultCryptoScope`: creation of four keys, its three private binding methods,
seal/open composition, shared reference lifetime and joint key/nonce destruction.
It invokes the existing native KDF, record and nonce owners. Its ABI never
returns a raw key and never accepts a caller-selected nonce or record key.

The original source is `src/mcp/runtime/operation_crypto.rs` at runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`, SHA256
`a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633`.
The exact source/image dependencies and authority table are in
`operation_scope_composition.json`.

## Authority and ownership

Only the trusted operation controller may invoke this ABI. Token construction
requires the exact bearer bytes to have already passed credential verification.
Syntax validation does not authenticate a token. Canonical request/policy bytes
and the trusted result-binding fields also come from that controller.

There is one private workspace and one nonce child per scope instance. Internal
references share that same instance; copying keys into another workspace is
not a clone. The caller owns reference admission and which live reference may
invoke a method. No serialized client handle or owner/session digest grants
access to this state. The current component proves serial shared lifetime;
the original concurrent `Arc`/mutex and HTTP/session capability admission
remain separate owners.

Initialization, retain and release are internal lifecycle operations. An active
or finally released instance cannot be initialized again. An initialization
that fails before committing a scope clears its temporary keys and returns to
the fresh state, so the trusted caller may try construction again. A new
independent instance may use a newly zeroed private workspace. It has its own
nonce accounting, as a new original constructor does.

## Fixed composition

| ID | Owner | Flags | Allowed callees | Private workspace |
|---|---|---:|---|---:|
| 0 | Test-only hex transport | 1 | 6, 7 | 16 MiB |
| 1 | Existing record owner | 1 | 2, 3, 4 | 3 MiB |
| 2 | Existing key derivation owner | 0 | None | 2,048 bytes |
| 3 | Existing SHA/codec owner | 0 | None | 1,184 bytes |
| 4 | Existing AEAD owner | 0 | None | 512 bytes |
| 5 | Existing nonce owner | 0 | None | 1,576,960 bytes |
| 6 | Private scope controller | 1 | 1, 2, 5, 7 | 3 MiB |
| 7 | Trusted deterministic entropy fixture | 0 | None | 128 bytes |

The KDF image is unchanged; its table output capacity is 128 bytes to admit
the original four-key constructor. Scope and record outputs are bounded at
2 MiB, AEAD at 1,048,640 bytes and entropy at 128 bytes. Nonce input is bounded
at 164 bytes; fixture entropy input at 48 bytes. Other image inputs use the
existing 8 MiB composition bound. The test root can invoke scope and fixture
controls only. It cannot directly invoke the raw KDF or record interfaces.

The entropy interface remains abstract. Scope issues exactly
`HRENT001 || wanted:u64le || zero:u64le`, with `wanted` equal to 32 or 12.
Success must return exactly the requested length. `0xfffffffd` means entropy
unavailable. Any other result or malformed completion retires the bundle.
The deterministic child under `tests/hia_native` supplies synthetic bytes,
partial failed fills and one deliberately short successful return for a real
ELF fatal-contract control. It is not the Linux `SystemEntropy` implementation.

## Request frame

Entry uses `(readbuf, mutbuf, mutbuf) -> u32` with disjoint buffers. A scope
request starts with 24 bytes: magic `HRSCOPE1`, operation `u64le`, and a reserved
zero `u64le`. The remainder is the operation-specific input.

| Op | Input after the header | Successful output |
|---|---|---|
| 1 | Already verified token, 32..4,096 bytes, each ASCII 33..126 | Empty; commit four derived keys and an empty nonce set |
| 2 | Empty | Empty; commit four independent, ordered 32-byte entropy fills and an empty nonce set |
| 3 | Nonempty canonical request context, at most 1 MiB | 64 lowercase hexadecimal request-binding bytes |
| 4 | Nonempty private idempotency key, at most 128 bytes | 64 lowercase hexadecimal idempotency-binding bytes |
| 5 | Nonempty canonical private policy, at most 1 MiB | 64 lowercase hexadecimal policy-binding bytes |
| 6 | Complete `HRREC001` op-4 binding/payload frame | Original sealed result packet |
| 7 | `HRREC001` op-3 binding frame followed directly by the packet, with no key prefix | Authenticated original payload |
| 8 | Empty | Empty; retain the same private instance |
| 9 | Empty | Empty; release one reference, destroying keys and nonce state on the last release |

The nested record fields and full u128 timestamp are as documented in
`operation_record_abi.md`. Both original payload kinds are preserved. Scope
inserts its private AEAD key into the record-child input. Seal additionally
inserts the nonce that its own entropy and reservation steps admitted.

## Ordering and persistent state

Verified-token construction validates token bytes, calls KDF op 5, initializes
the nonce child, then commits all four keys. Stdio construction performs four
separate 32-byte fills in the original AEAD/request/idempotency/policy order.
No scope becomes active until all four fills and nonce initialization succeed.

Seal checks the payload bound and calls record preflight before requesting
entropy. A valid request also needs enough caller output capacity before any
entropy or reservation occurs. It then requests 12 bytes, reserves the exact
operation/ledger namespace and nonce, and finally invokes record seal. Duplicate
or exhausted-budget refusal happens after the entropy request, as in the
original owner. A consumed reservation is never refunded after a later failure.
Open uses the existing record open owner without requesting entropy or changing
the nonce set. Packet size/magic admission precedes binding validation.

Private bytes 0..159 hold the lifecycle word, reference count, reserved words
and the four 32-byte keys at offsets 32, 64, 96 and 128. Lifecycle values are
0=fresh, 1=constructing, 2=active, 3=finally released, 4=fatal. Words from offset
160 hold temporary continuation state. The last 256 bytes are the existing
adapter-owned call footer. Child completions must match the full sequence,
target, spans, capacities, status and exact expected output length.

## Refusal and cleanup

| Return | Meaning |
|---|---|
| A bounded ordinary length | Successful output byte count |
| `0xffffffff` | Malformed scope or nested byte frame |
| `0xfffffffe` | Insufficient output/workspace capacity |
| `0xfffffffd` | Original private binding/token input refusal |
| `0xfffffffc` | Original payload limit exceeded |
| `0xfffffffb` | Invalid trusted result binding |
| `0xfffffffa` | Entropy unavailable |
| `0xfffffff9` | Duplicate nonce or scope budget exhausted |
| `0xfffffff8` | Retained result authentication/integrity unavailable |
| `0xfffffff6` | Invalid private lifecycle/reference state |
| `0xffffffe8` | Fatal child/continuation contract failure; destroy the entire bundle |
| `0xffffffe0` | Existing internal child-call continuation |

Refusals release no partial result. The caller output and its unused tail remain
unchanged. Active keys survive ordinary method refusals. Temporary scope bytes
from offset 160 through the request's monotonic high-water mark are cleared on
every completed request that used scratch. Failed construction also clears all
pending keys. Last release destroys the nonce child, clears the entire scope
private region, and leaves only the closed lifecycle word. Fatal refusal clears
that same region and leaves only the fatal word; an untrusted child completion
does not justify further use of the bundle.

Existing KDF/AEAD private clearing and the record owner's exact empty-SHA
sanitation contract remain in force. Normal final release tests also inspect
those child regions and the emptied nonce set. The readonly token and payload
inputs belong to the caller; reference admission, cancellation, EOF lifecycle
dispatch, register/stack erasure and constant-time behavior are not established
by these explicit private-workspace checks. The hex root is a test transport,
not a public MCP service or credential export interface.

## Qualification

The suite executes actual native images and the fixed persistent ELF, checks
ordered partial entropy failures, clone sharing, all 16,384 nonce reservations,
budget/error order, authenticated refusals, full timestamp/payload boundaries,
exact capacities, child-result/acknowledgement controls and key destruction.
Python standard cryptography provides independent byte expectations. The locked
Rust oracle embeds the complete unchanged original crypto module and keeps real
original scopes, derived clones and nonce sets alive across each captured trace.
Fixture controls, adapter-only refusals, nonce-budget setup and actual original
scope calls are counted separately. Installing a named child-result fault marks
its entire session as outside original Rust replay before the outcome is known.
The corpus retains an explicit session/reason/row-count ledger and every native
row in those sessions, including mutated completion words and later releases.
Caller-capacity controls have their own retained records. These domains form a
disjoint accounting of all direct native requests; they do not become original
Rust matches by omitting a state-changing call. Aggregate qualification and
production activation remain separate gates.
