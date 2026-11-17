# Resolved session owner projection

This is a new isolated version of the registered serial caller-authority owner.
It preserves the existing request admission and first-call binding algorithm.
Only operation 3 and its result serializer are added. The previous unavailable
candidate and its unknown smoke execution are not inputs or qualification.

## Request and result

The existing private HRAUTR01 qualification transport remains unchanged:
lowercase ASCII hex of an eight-byte magic, three little-endian u64 fields
(operation, header count, payload length), ordered length-prefixed headers and
payload. New operation 3 requires an empty payload. Existing operations 0, 1
and 2 retain their input and result contracts.

Admission runs before operation dispatch. Operation 3 invokes the existing f8
binding owner before reading the bound state. A successful result is exactly:

| Offset | Size | Value |
| --- | ---: | --- |
| 0 | 8 | HROWR001 |
| 8 | 8 | Authenticated flag, little-endian u64, 0 or 1 |
| 16 | 64 | Lowercase hexadecimal owner, all 64 bytes |

These fields come from private, already-bound session state. The consumer must
use the current admitted CALL result and keep that borrowed result alive while
validating and copying its entire extent. A public request cannot provide this
projection as a credential or select private owner state.

The existing response transport prepends a four-byte semantic status, then
hex-encodes the full response. A successful operation 3 therefore produces 168
ASCII bytes. Semantic refusals retain the existing eight-byte status encoding.
A too-small output returns the existing capacity refusal after binding. A later
valid request observes the same binding; response capacity never resets it.

The existing trusted reconnect fixture creates fresh per-session state while
preserving credential crypto. Ordinary requests cannot invoke this lifecycle
event. HTTP parts without a verified extension do not select stdio fallback.

## Source and qualification boundary

The target is d3d75c30719db966b004756f610007a7c723729e. The complete unchanged
caller_scope.rs, operation_crypto.rs, main authentication segment, and owner
generation segment are retained by the reference recipe. Actual SDK contexts
are constructed by the reference harness. The stdio fallback is the complete
private native OS observation, separately identified as such; replay does not
pretend two independent random generators return identical bytes.

The new HIA source is c8762a6c08a7270e473b6868798de059cbee2443ad47c1cd49962fe5d27b4775.
Its first actual image is 795da0a7234853e9e1afbf8f993321a2f12aa86f16c06a6374a1913473693417.
The author proves all 31 other original function ASTs, including f8, identical,
and reconstructs the complete original f7 AST by reversing only the added edge
and operation bound. The nine-member packer changes only its exact root pins;
its mechanical syscall adapter and the other eight owners retain their sources.

This interface alone does not qualify concurrent Arc/Mutex behavior, current
HTTP listener startup, public routing, annotation integration, or replacement
of the whole runtime. The old optional-HTTP qualification mode remains only a
declared private absent-extension fixture; it is not current target startup.
