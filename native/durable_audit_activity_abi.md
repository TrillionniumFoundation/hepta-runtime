# Audit activity registry, private ABI 1

This HIA owner models the original ACTIVE registry of string keys and weak
references to atomic booleans. It is distinct from result records, JobRecord,
read pins and audit store locks. One private state belongs to the actual runtime
instance; creating an independent registry for every public session would
change the original semantics.

The request is exactly 128 bytes: HRAACTQ1, operation at 8, token at 16,
boolean at 24, zero bytes 32..63, and a 64-byte lowercase hexadecimal request id
at 64 only for begin/query. All words are unsigned little-endian.

| Operation | Meaning |
| --- | --- |
| 0 | Initialize an empty state |
| 1 | Begin: create a strong true marker and replace this key's weak mapping |
| 2 | Clone a live strong marker |
| 3 | Store the exact boolean in a live marker |
| 4 | Drop one strong reference |
| 5 | Remove all dead mapped weak references, then query the selected key |
| 6 | Private observation of registry-mutex poisoning |

The 64-byte HRAACTR1 response contains status, token, active boolean, required
workspace length, mapped entry count, allocated marker count, and a final zero.
Statuses are 0 success, 1 explicit arena growth, 2 poisoned registry, 3 stale
token, and 4 reference/token overflow. Growth happens before insertion; the
caller preserves the complete old workspace and zero-fills the added bytes.
There is no application entry cap. Reference counts retain the original
isize::MAX bound, and generations do not wrap.

Workspace is a 128-byte header followed by 128-byte slots. Each allocated slot
contains id, nonzero generation, strong count, atomic boolean, weak-map flag and
reserved zeros. Replacing a key leaves old live holders intact. Dropping the
last holder leaves its mapped dead weak reference until a later query performs
the original whole-map retain. Begin/query refuse registry poisoning; atomic
store and strong-holder operations do not acquire that poisoned registry.

The owner expects an actual private critical section around registry access.
The sequential ABI controls and real History comparison use an actual QA
mutex. Final native shared-state synchronization is a distinct integration gate.
