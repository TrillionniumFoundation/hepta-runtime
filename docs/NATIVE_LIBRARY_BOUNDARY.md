# Native Rust library boundary

`hepta-runtime` provides **one** implementation of its policy-enforced
filesystem, job, PTY, SSH, inspection and MCP server capabilities. Cargo now
builds both:

- `hepta-runtime`: the existing CLI/MCP process, backed by `hepta_runtime::mcp`
- `hepta_runtime`: a Rust library for explicitly trusted host-side adapters

The executable imports the library instead of duplicating source modules.
This change does not create another executor, another policy owner or a
separate tool implementation.

## In-process integration seam

A trusted Rust host can link the existing runtime implementation without an
MCP serialization hop, for example:

```rust
use hepta_runtime::mcp::runtime::jobs::ProcessRefParams;

let reference = ProcessRefParams {
    host: "configured-host".to_string(),
    job_id: "known-job-id".to_string(),
};
```

An external Hepta adapter must still validate `RuntimeToolIntentV1`,
host/scope, generation, exact final-payload digest, idempotency key,
operation deadline, and an independently issued final-use grant **before**
calling any effectful function. It must map physical terminal observations
to `RuntimeReceiptV1`; returning an accepted RPC or process start alone is
not proof of completed effects. Unknown acknowledgements remain
reconcile-only.

The library does not authenticate a caller, grant model or filesystem
authority, instantiate policy for a caller, or declare a tool effect safe
merely because it was compiled in-process. All existing runtime host-policy
checks remain in force. MCP remains the boundary for external,
cross-process, and cross-host consumers.

## Verification

`cargo test --all-targets` should compile the same library implementation
used by the binary and exercise `tests/native_library_boundary.rs`.
Real native-adapter integration, independent final-use wiring, target-host
recovery, and cross-process equivalence tests are **follow-up blockers**;
they are not claimed as completed by exposing this library target.
