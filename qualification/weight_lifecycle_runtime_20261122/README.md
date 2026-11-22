# Persistent native weight-program lifecycle

This research executable compiles an authenticated EditProgram and connects it
to the real runtime canonical artifact owner and the existing full native
Hepta Neuron DAG/policy evaluator. It creates no second model store and never
changes a service or active model pointer. A configured `process_start` route
can own this explicit executable and argv; no new public MCP route is required.

## Interface

```text
hepta-weight-lifecycle-study run REQUEST SHA256 NEW_ROOT RESULT.json [CUT]
hepta-weight-lifecycle-study recover REQUEST SHA256 ROOT RESULT.json
hepta-weight-lifecycle-study next-task REQUEST SHA256 ROOT RESULT.json
```

The request is a strict `hepta.weight-lifecycle-request.v1` JSON object, role
`exposed_research_execution`, containing `source_bridge`, `source_gzip`,
`semantic_contract`, and `program` pins (`path`, `bytes`, `sha256`), the original
`decoded_source` SourcePin, the existing edit `domain`, and a policy. The policy
contains complete `primary`, bounded `preservation` and `next_task` public tasks,
`minimum_gain`, and `maximum_preservation_loss`. Pin paths must be explicit
absolute paths. Relocation produces a separately identified request; it does not
alter model, law, profile, program or semantic-contract bytes.

Run authenticates the source gzip and complete bridge against the reviewed
profile and actual protected frontend. It recomputes the snapshot and compiler
output; caller-supplied serialized preparation is never execution authority.
The source, contract, program, request and evaluator binding are durably captured
in the new private root. The isolated runtime configuration allows only that root
and stores canonical `wa1` artifacts under its private state directory.

The evaluator binding includes the exact running binary, entire request and
native arithmetic identity. Complete forward, own-policy occupancy, terminal
reward, expense, value decomposition and performance-difference residuals are
computed independently of the edit equations. Positive use requires strictly
greater gain than the declared minimum and all preservation tasks passing.
Successful and rejected evaluations both restore the original as a canonical
inverse artifact. This proves research execution, not a generalization claim.

Recover re-authenticates the retained bytes and recomputes the same intent. It
never re-evaluates or manufactures acceptance. Journal decisions bind retained
full evaluator outputs; losing or changing those outputs prevents successful
completion. A fully captured request interrupted before its first journal record
can complete an explicit KEEP with no publication. Earlier partial capture is
refused, has no owner effects, and requires a separately identified fresh root;
this is not a claim of recovery from arbitrary storage faults.

Next-task reads the actual inverse artifact, verifies exact original bytes and
semantic identity, then performs a complete native task evaluation on its
predeclared next task. It uses the retained source if the preceding decision was
KEEP before any publication.

## Fault and cost evidence

Fault injection parks only at named boundaries in a fresh isolated research run.
An external supervisor sends real SIGKILL and starts a new process for recovery.
The process includes compiler, coordinator, canonical owner and evaluator;
there is no external evaluator child left behind by supervisor death.

Per-policy graph-start, DP-start and DP-complete files distinguish attempted work
from known completion. If a process dies between computation and its durable
completion record, completion is unknown, never imputed as zero. Per-task full
outputs are individually bounded and hashed by the final evaluation record.
External wall/CPU/RSS measurements include failed processes. The canonical owner
copies/hashes complete checkpoints; patch byte count is not the I/O cost.

The worker source is checked and linked against the complete root library in
both feature modes. Root Cargo.toml and Cargo.lock remain unchanged. These gates
are scoped qualification and do not replace full runtime release qualification,
cross-version journal migration, power-loss testing or production adoption.
