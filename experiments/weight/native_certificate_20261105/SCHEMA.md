# `weight_continuation_certificate` schema v1

The actual MCP `tools/list` response is retained by the corpus driver as
`TOOL_SCHEMA.json`; it is the generated schema for the built binary. This note
defines the semantic and byte-level contract.

## Request

The top-level request, `source` and each `rows` object reject unknown fields.
Strings representing bytes use lowercase hexadecimal with exact lengths.

| Field | Meaning and checks |
|---|---|
| `semantics` | Exactly `binary64_rne_gradual_separate_products_sum49_v1`. A declaration, not an environment probe. |
| `checkpoint_json` | Original UTF-8 JSON bytes, 1 through 1,048,576 bytes. |
| `expected_checkpoint_sha256` | SHA256 of those UTF-8 bytes; 64 lowercase hex characters. |
| `expected_witness_sha256` | SHA256 of the binary witness sequence defined below. |
| `source.fit_id` | Unsigned 32-bit fit ID, equal to the checkpoint's `fit`. |
| `source.protocol_sha256` | Caller declaration binding the producer protocol. |
| `source.feature_source_sha256` | Caller declaration binding the feature implementation. |
| `source.teacher_source_sha256` | Caller declaration binding the teacher implementation. |
| `source.original_witness_record_sha256` | Caller declaration binding an upstream record that this tool does not read. |
| `rows` | One through 8,192 witness rows. |

The checkpoint must declare `schema="joint-policy-v1"`, `family="renewal"`,
`head_dimensions=[85,48,4]` and matching `fit`. `network.w2` must contain four
finite rows of 48 binary64 numbers, and `network.b2` four finite numbers. The
first three rows and their biases are extracted in head-major order. Typed
Serde parsing rejects duplicate known checkpoint fields. Other checkpoint
fields, including `w1` and `b1`, are not used or validated. This is not a full
checkpoint execution-graph validator.

| Row field | Meaning and checks |
|---|---|
| `source_row` | Unsigned 32-bit upstream row identity. |
| `state_sha256` | Caller-supplied state identity, 32 bytes. |
| `teacher_table_sha256` | Caller-supplied teacher-table identity, 32 bytes. |
| `hidden_f64_le_hex` | Exactly 49 binary64 values, each IEEE 754 bits in little-endian order: 392 bytes / 784 hex characters. Finite, each absolute value ≤ 1, last coordinate exactly +1. |
| `hidden_sha256` | SHA256 of the 392 raw hidden bytes. |
| `multiplier_f64_le_hex` | One finite nonnegative binary64 in 8 little-endian bytes / 16 hex characters. Positive and negative zero are algebraic zero. |
| `teacher_q_f64_le_hex` | Six finite binary64 values in fixed action order, 48 bytes / 96 hex characters. |
| `legal` | Exactly six JSON booleans in action order. |
| `target_action` | 1=WAIT, 2=READ or 3=REPAIR, and the first legal maximum of the supplied six Q values. |
| `competitor_action` | A different legal action in 1 through 3. |

The six-action ordering is inherited from the pinned renewal producer: STOP,
WAIT, READ, REPAIR, SUBMIT-0, SUBMIT-1. The tool checks a weak pairwise necessary
ordering and deliberately does not impose a positive margin, first-max strict
win, STOP/terminal comparison, or Belief constraint.

The same `(source_row, target_action, competitor_action)` may not appear twice.
For the same `source_row` with different competitors, the state digest, teacher
table digest, hidden bytes, Q bytes, mask and target must all match. Source row
IDs need not be consecutive; omitted zero-multiplier constraints do not affect
a supplied witness proof. Completeness relative to all upstream TRAIN states
is a separate producer/replay responsibility.

## Binary witness identity

SHA256 is computed over the following concatenation without JSON encoding or
whitespace. All integers below are unsigned little-endian; all hex fields are
decoded before hashing.

1. ASCII bytes `hepta.weight.continuation-witness.v1` followed by one NUL byte.
2. Row count as a 64-bit integer.
3. For each row, in request order: `source_row` as a 32-bit integer; 32 state
   bytes; 32 teacher-table bytes; six mask bytes (0 or 1); one target byte; one
   competitor byte; eight multiplier bytes; 392 hidden bytes; 48 Q bytes.

`hidden_sha256` is checked independently and is not repeated in this sequence.
All top-level fields, including source declarations and expected digests, are
also bound by `request_sha256`, the SHA256 of Serde's canonical serialization
of the typed request. Its size is reported as `canonical_request_bytes` and
limited to 8 MiB. This canonical encoding is **not** claimed to preserve the
original wire JSON bytes. The raw checkpoint string is preserved and hashed
separately.

## Response and exact quantities

The response includes the checkpoint/witness/request hashes, supplied source
declarations, all 147 extracted center binary64 bytes and their SHA256,
implementation and arithmetic source hashes, row count, exact proof values,
limits, elapsed operation wall time, and explicit qualification boundaries.

Every exact scalar has this representation:

```json
{"numerator_hex":"-3", "binary_exponent":-12, "denominator_hex":"1"}
```

Its value is `int(numerator_hex,16) * 2^binary_exponent /
int(denominator_hex,16)`. Denominators are positive. Numerators are signed hex;
nonzero numerators are normalized to remove powers of two. Zero may use any
reported binary exponent without changing its value. This is an exact rational
representation, not a decimal approximation.

`proof` includes `radius_squared`, integer `radius_upper`, all 147 components of
`dual_vector`, its squared norm, three F64 error bounds, weighted F64 error,
number of nonzero multipliers, and the separate ideal and F64 sign/squared
comparisons.

| Verdict | Meaning |
|---|---|
| `F64_NECESSARY_SYSTEM_INFEASIBLE` | Both the declared F64 necessary relaxation and the ideal system have a checked strict separation. F64 interpretation is conditional on the declared execution semantics. |
| `IDEAL_REAL_ONLY_INFEASIBLE` | Ideal-real separation passes; the conservative F64 relaxation does not. Do not claim the F64 ordering was excluded. |
| `NOT_CERTIFIED` | This witness does not strictly separate the system. This is not evidence of feasibility or model quality. |

Malformed identities, dimensions, values, actions, sizes, deadlines or worker
capacity produce an error. They do not produce a positive mathematical
certificate. Native MCP qualification retains these errors explicitly.

The output denies the following qualifications regardless of verdict:
`external_source_authentication`, `hidden_or_teacher_program_reexecuted`,
`hardware_arithmetic_semantics_verified`, `independent_holdout_verified`,
`task_value_improvement_qualified`, `whole_network_impossibility_qualified`,
`production_eligible`, and `weights_modified`. `gradient_steps` is zero.
