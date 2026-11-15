# Public installed-handler registry

This fixed Linux x86-64 executable connects the actual HIA SDK message decoder,
persistent connection admission, installed configuration/regex graph and three
implemented method bodies: `host_list`, `effective_config` and
`execution_shadow_admit`. It accepts `--runtime-config FILE`; stdin cannot
select, install, reload or replace administrator configuration. The final
runtime image has no Python, Rust, libc or dynamic-loader dependency.

The qualified executable has 17 embedded HIA images, 4,439,495 bytes and SHA256
`fad9c8aab719e75b8011a25efff7b6835a54f5046b14980d8831a78c6c764b5a`.
Its fixed prefix is 6,185 bytes; all image bodies and relative-call targets are
verified individually after the separate HIA packer executes.

## Ownership and fixed calls

| IDs | Owner and admitted children |
| --- | --- |
| 0 | Immutable configuration; children 1/2/3/4 |
| 1 | Configuration filesystem effects; the sole syscall-effect owner |
| 2/3/4 | Typed configuration, ordered validation, policy identity |
| 5 | Public tool dispatch; only installed config 0 or execution controller 6 |
| 6 | Execution controller; typed JSON 7, installed host lookup 0, then core 8 |
| 7/8 | Original execution typed admission and deterministic shadow validation |
| 9 | Public SDK request/notification/response/error decoder |
| 10–15 | Regex syntax, Unicode data, HIR, NFA, matcher and controller |
| 16 | Persistent modern/legacy connection admission and initialization |

Validation 3 calls regex controller 15. The controller only calls 10/12/13/14;
syntax, HIR and matcher can query the immutable Unicode image 11. These
regex calls have no descriptor or OS effect capability.

The fixed adapter feeds each complete line to 9, then the resulting typed
projection to 16. Direct handshake/admission responses come from 16. Admitted
ordinary requests reach 5. The adapter does no JSON, host, method, mode or
path interpretation.

## Public input and persistent state

The explicit raw line profile is 8 MiB, with an additional CR/LF framing span.
Exactly one final CR is removed; empty lines are ignored. A final nonempty EOF
tail is decoded as a real frame. The decoder preserves the locked SDK's
syntax-versus-data transport behavior, ID rules, duplicate handling and exact
serde Number domain. A raw frame above the declared bound exits without a
partial response and closes owned configuration descriptors.

`HRCJQ001`/`HRCJR001` and `HRCNQ001`/`HRCNS001` retain the separately qualified
SDK owner ABIs. Decoder output is at most 64 MiB; connection admission is at
most 128 MiB. Router input and output each have a 128 MiB bound and its private
workspace is 256 MiB. The shared fixed mapping is 4,194,381,824 bytes of lazy
virtual address space. Offsets above 2 GiB are explicitly zero-extended before
addition to the mapping base.

Initialization and repeated initialization are handled by 16, including sticky
modern mode and updated peer information. Pre-initialize ping does not select
a mode. The first ordinary request and later requests retain their different
metadata/version error precedence. The actual method name is
`server/discover`; `discover` is an ordinary unknown custom method.

## Public router input and child receipt

`public_tool_dispatch.hepta` consumes an entire `HRCNS001` admitted event. It
checks its header, reserved words, span ranges and nested `HRCJR001` projection
before any public output or child call. It does not accept raw public JSON as
an administrator or child-call capability.

For CallTool, canonical arguments come from the actual SDK serde Value owner.
Missing and explicit `null` arguments both become `{}`, matching the SDK
`Option<JsonObject>` contract. Empty parameter structs reject the first sorted
unknown key with the original `Parameters` diagnostic. Execution calls use
`HXSREQ01` and retain typed-parameter-before-host-before-record-validation order.

The router uses the fixed `HIACAL01` footer at `workspace_length - 256`.
Sequence numbers increase across calls. Input region is the private router
workspace; output also stays in a disjoint private workspace span. Targets
are exactly 0 and 6. The full target, region, offset, length, capacity, result,
sequence, completion flag and reserved words are checked on resumption.
Malformed private completion leaves the pending request resumable. Public
output shortage emits no bytes and resets the completed request phase before
the next request; it does not undo an already completed child action.

The child result is `HRCFGM01` plus status, native diagnostic category, text
length and exact UTF-8 text. The diagnostic category is not reserved and does
not replace the original error text. The router emits SDK content and `isError`, escaping
IDs and text itself in HIA. `resultType: "complete"` is emitted only where the
effective context version requires it; 2025-06-18 response bytes do not include
that field. The exact catalog is sorted by the real SDK ToolRouter and uses
the original schema-cleaning helpers and annotations.

Internal failures are `0xffffffff` for malformed private contracts,
`0xfffffffe` for capacity and `0xffffffe0` for a pending fixed child. None of
these numeric internal statuses is silently converted to a fabricated public
method result.

## Qualification boundary

The complete original reference includes the unchanged installed configuration,
host lookup, execution implementation and the three public method bodies. It
uses a fixed three-route SDK projection. It intentionally omits the outer
`server.rs::call_tool` owner-binding, audit, cancellation completion and result
retention path. The separately retained connection corpus qualifies the SDK
handshake/default dispatch behavior; it does not implement the runtime's
custom resource or notification services.

This profile is not production activation and does not change any original
handler migration/removal flag. Shared audit/results and other runtime methods
must be connected before it can replace the full public runtime.
