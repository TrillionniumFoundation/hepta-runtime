# Private scope with real Linux entropy

This component connects the existing HIA scope, record, KDF, SHA, AEAD and nonce
owners to the existing HIA Linux entropy policy. The HIA composition packer
owns the complete static ELF and its syscall boundary. The scope and entropy
policy sources are unchanged. No Python or Rust semantic dispatcher runs in
the executable.

The original owner is `src/mcp/runtime/operation_crypto.rs` at runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`, Git blob
`0c07318a6d85efb920069ce4f190c4f2ed56e84f`, SHA-256
`a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633`.
The compiler remains Hepta `d3e2c90173cf733e42b299d0c4274df4b593a12f`.

## Exact authority table

`scope_os_profile.json` fixes every source digest, actual image digest, image
length, slot, capacity, flag and call mask. The native HIA packer computes the
SHA-256 of actual image bytes before granting entropy privilege. A matching
descriptor digest alone is insufficient.

| Slot | Owner | Flag | Call mask | Input bytes | Output bytes | Private workspace bytes |
|---|---|---:|---:|---:|---:|---:|
| 0 | Test hexadecimal transport | 1 | 64 | 8,388,608 | 8,388,608 | 16,777,216 |
| 1 | Record | 1 | 28 | 8,388,608 | 2,097,152 | 3,145,728 |
| 2 | KDF | 0 | 0 | 8,388,608 | 128 | 2,048 |
| 3 | SHA codec | 0 | 0 | 8,388,608 | 32 | 1,184 |
| 4 | AEAD | 0 | 0 | 8,388,608 | 1,048,640 | 512 |
| 5 | Nonce ledger | 0 | 0 | 164 | 64 | 1,576,960 |
| 6 | Private scope | 1 | 166 | 8,388,608 | 2,097,152 | 3,145,728 |
| 7 | Linux entropy | 4 | 0 | 24 | 128 | 1,024 |

The root calls only scope 6. Scope 6 calls record 1, KDF 2, nonce 5 and entropy
7. Record 1 calls KDF 2, SHA 3 and AEAD 4. Only entropy slot 7 may request this
OS effect, with scope 6 as its immediate caller. Requests cannot select a
device, raw descriptor, arbitrary image, destination or extra authority bit.

Admitted flags are exactly `{0, 1, 3, 4}`. Existing flag-3 file IO stays in its
separately pinned owner and slot; the complete worker and 30-second guard are
unchanged. Future authority profiles require separate fixed tables and actual
new executable evidence.

Metadata starts at offset 8,752; its RIP-relative displacement is at offset
228. The prefix SHA-256, normalizing only the two ELF segment size words, is
`db41d6cf9664e59dcd216e2d0c7df398fc945c8df0a7e73b6137c97dfbf73273`.
Qualification checks that prefix, pointer, every descriptor, actual image,
source digest, alignment padding and private workspace placement.

## Scope and entropy ordering

The root uses the existing private `HRSCOPE1` ABI through a test hexadecimal
transport. It is not a registered public MCP tool or a credential verifier.
Its synthetic token represents an already admitted private credential.

The unchanged scope performs four ordered, separate 32-byte fills for stdio
construction. A failed fill clears uncommitted keys and permits a subsequent
attempt. Seal validates payload and binding before requesting 12 nonce bytes,
then reserves the nonce before derivation/encryption. Open authenticates through
the record owner. Exact u128 timestamps, framing and both payload kinds retain
their separately qualified record semantics.

The entropy request is the existing 24-byte `HRENT001` frame: magic, little-
endian u64 wanted bytes and a zero reserved word. The policy admits 0..128
bytes. Its `HIAENT02` effect starts at private workspace offset 256. The full
field layout is in `entropy_abi.md`. Slot, caller, sequence, phase, destination,
remaining width, reserved words and acknowledgement are checked before effects.

The unchanged policy probes `getrandom` with zero length once. Probe `ENOSYS`
or `EPERM` selects the file backend: fixed `/dev/random` open, readiness poll,
close, then fixed `/dev/urandom` open and caching. Opens preserve the original
`O_CLOEXEC` flags. Interrupted calls and partial destination advancement follow
the original backend. Ordinary errors and scope release retain the selected
backend, cached descriptor and monotonic effect sequence.

The fixed entropy syscall family is `getrandom(318)`, `openat(257)`, `poll(7)`,
`read(0)` and `close(3)`. Paths and raw descriptors stay private. Original
readiness/entropy blocking semantics remain; no backend timeout is widened or
introduced. Test response/cleanup deadlines are 15 seconds, not runtime entropy
timeouts.

## Lifetime and cleanup

Serial clone/release shares one nonce ledger and keeps keys until the last
reference. Concurrent `Arc`/mutex capability and a concurrent public service
remain outside this qualification.

The adapter tracks temporary random and cached urandom FDs independently. It
retires a slot before one close attempt and never retries close on `EINTR`.
Fatal child contracts, impossible errno, EOF and transport failure enter common
cleanup. Ordinary entropy failures clear transient bytes; normal scope release
retains the process-level cache.

Exit cleanup closes retained entropy FDs, clears all eight private workspaces
and the 8 MiB transport output, and retires private sequence/poll/FD state.
Actual controlled-child memory inspection covers 33,039,048 bytes per native
process: 24,650,400 workspace bytes, 8,388,608 output bytes and 40 adapter bytes.
This does not claim erasure of caller input, stack/registers, swap or unrelated
memory.

Original Rust leaves its static urandom cache to process exit; the native
adapter explicitly closes it. Comparison preserves this difference: only
opaque FD values and the native final cached-urandom close are normalized.
The original trace must separately contain no explicit cached-urandom close.

## Actual execution domains

The native-only kernel suite runs 37 actual processes and 238 responses, plus
two fatal contract and two transport requests without a response. Its 519
SystemEntropy notifications comprise 371 controlled and 148 kernel
completions. Every process has actual idle and final cleanup inspections.

The locked Rust recipe invokes the complete unchanged original module through
a private access shim. It calls actual stdio construction, seal/open, binding,
clone and drop; no fixture entropy owner replaces `SystemEntropy`. Across 31
original processes, 226 responses represent 220 original-owner calls and six
adapter-only state refusals. Its 469 SystemEntropy notifications comprise 363
controlled and 106 kernel completions. This recipe also reruns all 37 native
processes, reported as additional executions.

Exactly 114 deterministic responses compare complete input/output digest
records. Ordinary random bytes are not expected to match. Two real-random
cross-owner opens instead authenticate plaintext from records sealed by the
opposite owner.

The original standard-library HashSet `RandomState` initialization additionally
produces exactly one observed seed syscall per process. There are two admitted
Linux/libc paths: a 16-byte `GRND_INSECURE` request (flags 4), and a 32-byte
flags-zero refill through the public vDSO/libc random interface. These describe
observed syscall profiles, not a mapping from Rust versions: the exact same
Rust 1.95 executable exhibited the first profile on the Ubuntu CI runner and
the second on ai395. Freshly compiled Rust 1.99.1 also exhibited the second.

All 31 calls remain in each complete replay. Before fault injection or
SystemEntropy counting, the supervisor checks the owned child's actual
libc/vDSO ELF symbol and the exact length/flags pair, and lets the auxiliary
call reach the kernel unchanged. Flags 4 can never enter a SystemEntropy
controlled completion. Duplicate seed calls, unknown profiles,
invalid symbol ownership and a mixture of seed profiles within one replay are
refused. Each receipt retains its module hash, symbol bounds, instruction
offset and exact position among SystemEntropy events. The separate 8-byte,
flags-one process-runtime initialization call is recorded once, before any
transport input and before any other random syscall. Every original getrandom
notification must be accounted for: 236 SystemEntropy calls, 31 standard-library
seed calls and 31 process-startup calls, for 298 per complete original replay.
Unknown flags, late or duplicate startup requests and omitted notifications
are refused. Output mismatches never select which owner calls are excluded.

Six predefined native-only cases cover impossible errno, oversized completion
and malformed/broken transport. They are not original Rust comparisons. The
packer suite runs 103 actual calls: two valid packs, 99 admission refusals and
two capacity refusals. It also rejects 37 consistently rehashed ELF mutations
and verifies seven exact relocated SHA function bodies. Nine evidence-control
groups accept five complete actual reports, reject 49 corrupted receipts and
25 classifier inputs, and check nine valid classifications. These controls
add zero native or Rust calls.

The seed-profile repair was replayed against the exact failed-run native ELF
and Rust 1.95 binary in GitHub Actions run `43613933669`. All native and original
cases passed under the unchanged 180-second suite limit. Independent ai395
replays passed the complete native domain and both Rust 1.95 and freshly built
Rust 1.99.1 originals. Native HIA sources, all eight images, the packer and ELF
are unchanged. This component repair is not an aggregate runtime qualification.

Initial local cleanup `EPERM`, early classifier failures, the first test
sentinel mismatch and an archival-path failure remain separately retained.
Successful final suite reports do not rewrite these failed observations.

## Qualification integration

`scripts/hia_native_scope_os_build.py` exposes
`build_scope_os(hepta, build_root, source_root=repository_root)` and
`--hepta` / `--build-root`. The static ELF needs no authoring assembler or
semantic Python fallback at execution.

Register module key `operation_scope_os`, builder `scope_os_composition`,
source `native/operation_scope.hepta`, environment `HIA_SCOPE_OS_MANIFEST`.
The helper `SUITES` declares three mandatory processes and their receipt
environments under `operation-scope-os-reference/`. After all pass,
`write_corpus(root, folder, exact_profile(root, manifest))` creates the native
corpus. `native_evidence(root, output, report)` rechecks compiler receipts,
sources, actual images/table, independently tested leaves and raw observations.
The native phase leaves original comparison `PENDING`.

The next mandatory locked Cargo recipe builds
`tests/hia_native/scope_os_oracle/Cargo.toml`, executable
`hia-operation-scope-os-reference`, with `HIA_REFERENCE_RUNTIME` bound to the
frozen source. Rerun `test_scope_os.py` with `HIA_SCOPE_OS_REFERENCE_BINARY`
and its exact `HIA_SCOPE_OS_REFERENCE_SHA256`; `HIA_SCOPE_OS_RESULT` writes
`scope-os-original.json`. `paired_evidence` validates the complete domains.
Retain build command, source/binary digests, process status, stdout/stderr and
the entire paired receipt. Sanitize inherited HIA overrides before setting
qualifier-owned values; preserve standalone development overrides.

The reference lock pins ring 0.17.14, getrandom 0.2.17, serde_json 1.0.151,
zeroize 1.9.0 and libc 0.2.191. The original runtime lock uses another libc
patch version: this is complete original-owner source comparison under the
recorded reference lock, not reproduction of the entire old dependency graph.

Fresh actual executables built by this packer also passed the old seven-image
service, generic bridge, nonce, record and fixture-scope suites, including
unchanged real 30-second worker deadline controls. Production handler,
migration-complete and legacy-removal flags remain unchanged. Authority
admission and concurrent scope capability are separate remaining owners.
