# Private typed results and response metadata

Three native byte owners have independent, complete qualification domains:

| Owner | Actual native domain | Fresh original replay |
|---|---|---|
| `binary32_json` | 541,693 patterns in an exact-import bulk fixture; 1,045 direct production entries and six controls | 541,693 values serialized by the locked Rust serializer |
| `typed_result_json` | 5,249 Complete/ErrorData cases, including two exact eight-MiB bodies, and fourteen controls | 5,249 cases plus two independently executed size probes |
| `request_result` | 1,926 metadata/budget cases, 4,702 owner entries, 1,966 real Value calls, 762 real typed-serializer calls and forty-nine controls | 1,926 cases plus forty-four actual typed budget probes |

Native testing uses complete original observations retained from earlier actual
Rust executions. These fixtures supply typed canonical projections, including
the distinction between `Some(Value::Null)` and `None` and the f32 annotation
representation. The native tests execute the new compiled images and retain
every output. They explicitly report zero fresh Rust executions.

The original phase builds one new Cargo project containing three executables.
Its one-hundred registry dependencies retain the exact original lock versions,
sources and checksums. Every `.crate` archive must match its locked package
checksum, and every archived member must match the actual Cargo source tree.
Only Cargo's two root metadata markers are excluded from that source inventory.
All one hundred archives are retained and rechecked at evidence admission; the complete
175-file rmcp SDK and selected number-serialization crate inventories are also
bound. The metadata reference copies eleven original source blocks and the
complete JSON size counter. Three ordered recipes execute all 548,914 inputs,
including the probes, and compare every byte with the already executed native
corpora. The recipes share their writable Cargo target only during the first
build; later recipes reuse verified, retained executables without parallel
mutation. No original implementation is used by a production runtime path.

Four native suites include sixteen damaged-evidence controls. After all Rust
recipes have drained, a separate process checks thirteen additional damaged
completion, compiler, source and full-output receipts and restores every byte
and mode. Raw corpus bytes are retained in gzip form; compression does not
truncate records or replace execution. Fixed process budgets remain 180
seconds with a separate three-second cleanup allowance where used. Build and
reference helpers do not claim complete cleanup after an external SIGKILL of
their own process.

The fixed eight-byte word helpers in these private owners use eight ordered
byte accesses instead of a counted loop. The binary32 interval arithmetic and
the public Value owner are unchanged. Source composition verifies the exact
new helper IR against a fixed authoring expression and binds the preceding
helper IR to the pinned binary64 or text-budget source. The typed owner keeps
29 unchanged imported functions plus three local text-budget word helpers;
the request owner keeps five unchanged imports plus its three local helpers.
The typed owner also imports the revised binary32 word helpers. Every bulk
formatter function remains identical to its production counterpart. All
qualification domains, byte comparisons and process budgets above remain in
force.

## Remaining public lifecycle boundary

These are private typed result seams. They do not activate public tools,
install caller identities, store request results, or complete audit records.
Complete/ErrorData typed serialization is qualified; Task/InputRequired
serialization is outside the typed serializer. The metadata owner preserves
opaque non-Complete bodies. Its Value input profile has the existing eight-MiB
body and depth-127 bound; exceeding a declared buffer profile is a capacity
refusal, not the original final-wire budget error.

Public activation still needs the trusted SessionOwnerBinding projection,
original pre-dispatch audit and durable request admission, result retention and
acknowledgement ordering, and exact typed bytes passed to storage before
protocol-version normalization. The original completion and retention branches
read cancellation separately; a caller must preserve those two observations.
All 125 production-handler migration rows and all global replacement/removal
flags remain unchanged.
