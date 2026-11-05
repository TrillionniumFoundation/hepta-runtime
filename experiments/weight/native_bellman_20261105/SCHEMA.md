# `weight_bellman_plan` contract

The method evaluates a caller-declared finite directed acyclic graph with a
**risk-neutral, additive recurrence** over the supplied values, rewards and
fees. It does not read a checkpoint or identify the correct environment law.
The tool returns JSON text through the existing Runtime MCP transport.

## Request

The only root property is `states`. Every state contains exactly six `actions`,
in the fixed order **STOP, WAIT, READ, REPAIR, SUBMIT_0, SUBMIT_1**. `null` means
illegal. All fields shown below are required; unknown fields are rejected.

```json
{
  "states": [
    {"actions": [{"kind":"terminal","value":2.0}, null, null, null, null, null]},
    {"actions": [{"kind":"terminal","value":0.0}, null, null, null, null, {"kind":"terminal","value":4.0}]},
    {"actions": [
      {"kind":"terminal","value":0.0},
      {"kind":"continue","branches":[
        {"probability":0.25,"successor":0,"reward":0.0,"fee":0.5},
        {"probability":0.75,"successor":1,"reward":0.0,"fee":0.5}
      ]},
      null, null, null, null
    ]}
  ]
}
```

This graph gives values 2, 4 and 3, with actions STOP, SUBMIT_1 and WAIT.

| Object | Property | Contract |
| --- | --- | --- |
| Request | `states` | 1–4,096 states, children before parents |
| State | `actions` | Exactly six slots, at least one legal; at most two continuing actions |
| Terminal action | `kind`, `value` | `"terminal"` and a finite F64 value |
| Continuing action | `kind`, `branches` | `"continue"` and 1–3 ordered branches |
| Branch | `probability` | Finite and nonnegative |
| Branch | `successor` | Unsigned 32-bit index strictly below the containing state index |
| Branch | `reward` | Finite F64, including negative values |
| Branch | `fee` | Finite and nonnegative F64 |

For every continuing action, the sequential F64 sum of its probabilities must
be within `1e-12` of one. Values are used exactly as supplied after decoding;
there is no renormalization. Even a zero-probability branch must satisfy the
structural and finite-value checks and counts toward the branch budget.

## Declared recurrence

Each continuing action starts with `total = +0.0`. In the supplied branch
order, a nonzero-probability branch performs these separate F64 operations:

```text
rewarded = child_value + reward
continuation = rewarded - fee
contribution = probability * continuation
total = total + contribution
```

Zero-probability branches are skipped during arithmetic. No fused
multiply-add, fee extraction from the sum, reordering, hidden discount or
probability normalization is introduced. Every intermediate must be finite.
The first legal action is the initial candidate; later actions replace it only
when their Q value is strictly larger. Near-tie diagnostics do not alter this
selection rule.

This recurrence does not implement entropic risk, exponential-moment or
log-sum-exp aggregation, a general NDU objective, or an FBSDE solver. Branches
can declare their own numeric fees for the additive expectation. The planner
does not reconstruct joint state/cost laws or implement a general
risk-sensitive recursion for correlated random fees. Such objectives require
a different explicitly specified recurrence and separate qualification.

The graph may contain both canonical value nodes and representative query
nodes. Query nodes can reference the same earlier canonical nodes while
declaring their own branch fees. This preserves a caller's distinct sunk-cost
rounding contexts without introducing hidden state into the native planner.

## Response and identity

`states` has one entry per request state, with `q` (six finite values or null
for illegal slots), `value`, and integer `action` in 0–5. Additional fields
describe dimensions, resource admission, probability-sum errors, exact and
near ties, and a repeated F64 consistency residual.

`request_sha256` hashes the typed canonical `serde_json` request. It is
explicitly different in meaning from a raw JSON-RPC transport hash. `plan_id`
binds that commitment, the fixed semantic version, and the SHA256 of the
compiled Bellman module's source. The result also exposes that module hash.
It does not claim to hash the complete compiler/dependency closure. The
qualification independently pins the executable and the relevant source files.

The self-consistency residual recomputes the same declared F64 recurrence and
selection from the completed prefix values. It is a consistency diagnostic,
not a numerical error bound or a proof of real-arithmetic optimality. The
response explicitly reports checkpoint verification, environment-law
verification, real-arithmetic certification, independent holdout verification
and production eligibility as false.

## Resource scope

Admission limits are 4,096 states, 24,576 branches, 8 MiB of typed canonical
request bytes, an 8-million-unit conservative scalar-operation model, and a
checked 30-second solve deadline. Shape and byte checks occur after MCP request
decoding; the upstream transport is a separate layer. The operation model
includes validation, the forward dynamic program, repeated consistency checks,
selection and tie diagnostics. Serialization and hashing have their own byte
bound.

Two permits bound **this Bellman planner's independent pool**. They are not a
shared concurrency ceiling for all Runtime tools. The blocking worker retains
its permit until completion even when its caller is cancelled. The method has
no filesystem effects and does not publish or activate policy artifacts.
