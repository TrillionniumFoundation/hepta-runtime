# Native semantic continuation certificate

`weight_semantic_certificate` composes the existing native endpoint replay and
exact continuation witness checker in one Runtime worker. It computes the
causal states, hidden values, legal masks, teacher Q values and first-maximum
targets itself. No caller-supplied hidden vector, Q table, state, legal mask or
target is accepted. Source pins bind the selected compiled source bytes; they
are not a complete executable identity or external source authentication.

This first version covers one checkpoint, one public schedule and 1–128 causal
traces under `hepta.joint-renewal.endpoint-replay.v1`. It is deliberately a
single-schedule composition. It does not claim to reexecute the complete
previous five-fit, multi-schedule witness corpus in one request, find witnesses,
modify weights or establish model efficacy.

## Request

The outer object has exactly six fields:

| Field | Meaning |
| --- | --- |
| `replay` | The four-field `SemanticReplayParams` envelope from [semantic replay](weight-semantic-replay.md); includes exact request/core/target-contract SHA256 commitments. |
| `expected_join_source_sha256` | SHA256 of the compiled `src/mcp/weight_semantic_certificate.rs`. |
| `expected_semantic_adapter_source_sha256` | SHA256 of the compiled `src/mcp/weight_semantic.rs` admission, shared worker and bounded output adapter. |
| `expected_certificate_source_sha256` | SHA256 of the compiled `src/mcp/weight_certificate.rs`. |
| `expected_arithmetic_source_sha256` | SHA256 of the compiled `src/mcp/weight_certificate_exact.rs`. |
| `witnesses` | 1–256 distinct `(source_row, competitor_action)` selections with exact nonnegative multipliers. Every replay trace must be represented. |

Each witness contains exactly `source_row`, `competitor_action` and
`multiplier_f64_le_hex`. The multiplier is one finite nonnegative binary64 value,
encoded as 16 lowercase hexadecimal characters in little-endian byte order.
Positive and negative zero are both permitted; a zero witness contributes no
separation. Competitors are WAIT=1, READ=2 or REPAIR=3. The target is computed by
the semantic core, must itself be a continuation, and must differ from a legal
competitor. Terminal targets cannot enter this continuation-only matrix.

Unknown and duplicate structured fields are rejected. Repeated source rows in
the replay, repeated comparisons, missing/extra source-row references, stale
digests, nonfinite multipliers and illegal comparisons fail before a success
result. The core preserves the existing supplied-law, current-at-due,
representative-state, reduction-order and first-maximum semantics. Neither the
numerical algorithm nor the exact arithmetic and coefficient-ball definition
change. The semantic core gains an earlier-deadline entry point, so its source
identity changes and old executable qualification is not transferred to it.

## Native join and commitments

The operation verifies the compiled identities and exact replay envelope,
reexecutes the checkpoint and teacher, and generates `CertificateRow` values
directly from the resulting native objects. Source row identities are useful
join keys; they are not authenticated identifiers of an external dataset.

The state SHA256 commits to the compact JSON tuple containing a fixed domain
tag, checkpoint/public/core/contract digests and the reconstructed state. The
`teacher_table_sha256` used by the existing checker commits to a second
domain-tagged tuple with those identities and the ordered selected native
teacher rows: source row, state digest, exact Q bytes, legal mask and target.
It binds the selected reconstructed rows, not the entire cached Bellman table
or an external teacher file. Native hidden bytes and their SHA256, exact Q bytes,
legal masks and targets are retained in `generated_witness_rows`.

The exact verifier's existing binary witness encoding is recomputed from these
generated rows. Its source record uses the native fit, core digests, the SHA256
of the fixed single-schedule profile string as protocol identity, and the
canonical outer request digest as `original_witness_record_sha256`. That last
field is this selection request's identity, not a claim that an earlier
scientific witness file was authenticated.

The nested `certificate` retains the old supplied-row-only declarations because
that component still performs the same exact checker operation. The enclosing
`witness_semantics_reexecuted_and_joined=true` states how this operation obtained
its rows. This does not upgrade an arbitrary separately supplied certificate or
allow a caller to claim provenance merely by providing a semantic-result hash.

`NOT_CERTIFIED` is a valid mathematical result and is retained as such. A native
replay or a successful RPC is not necessarily an infeasibility proof. A proof
still concerns only the fixed 147 continuation coefficients, the original
coefficient ball and the selected necessary ordering system. It excludes no
useful partial edit, different representation, larger radius or other policy.

## Worker and resource boundary

| Resource | Limit or behavior |
| --- | --- |
| Replay request JSON | Existing 2 MiB UTF-8 limit; 1 MiB checkpoint and 16 KiB public schedule inside it. |
| Complete canonical outer request | 3 MiB, checked through a bounded hashing writer. This is after transport deserialization, not a claim about transport allocation. |
| Traces/comparisons | 1–128 traces and 1–256 comparisons, with exact coverage. |
| Success JSON | Bounded to 1 MiB through the existing result writer. |
| Concurrency | One non-queued worker shared with `weight_semantic_replay`; permit covers admission, replay, join, checking and output serialization, including after caller cancellation. The standalone certificate API retains its own independent two-worker limit. |
| Outer result cutoff | 30 seconds from composite worker entry, checked around replay, during join/checking and after serialization. Late results are refused. |
| Semantic core computation | `replay_until` receives the earlier outer cutoff; its internal deadline is the minimum of that cutoff and its local 30-second cap. Entering the core does not renew the caller's allowance. |
| Exact checker | Receives the earlier outer deadline and cannot start a fresh 30-second allowance. |

These are cooperative computation/result checks, not a hard wall-clock process
kill. Cancellation does not interrupt an already running blocking worker; it
retains admission until that worker actually finishes. CPU/memory isolation of
the containing Runtime process remains the owner deployment's responsibility.

The tool opens no model or data files, starts no process and changes no weights.
Ordinary Runtime auditing remains active. Complete execution qualification must
also bind the Runtime source/lockfile/toolchain/feature set/build flags and actual
ELF, not just these six source/contract pins. External input authorship, hardware
arithmetic error bounds, held-out efficacy, whole-network impossibility and
production eligibility remain unqualified.

## Targeted verification

The synthetic tests cover a known exact separation and non-certificate cases,
independent reentry of generated rows into the existing checker, all source
pins, unknown/duplicate fields, hidden/Q/state/mask/target injection, row
coverage and duplication, terminal/illegal comparisons, exact multiplier
validation, byte/deadline boundaries, native-result identity and retained shared
worker admission after cancellation. The existing isolated real-MCP test also
checks discovery, successful delivery, six rejection cases and continued use.

The relevant commands are `cargo test --locked --lib --all-features
weight_semantic -- --test-threads=1` and the matching `weight_certificate`
filter, repeated with `--no-default-features`, plus formatting and strict
Clippy. Synthetic controls are engineering fixtures, not new scientific
samples. Record actual execution results separately; test source alone is not
a passing qualification.
