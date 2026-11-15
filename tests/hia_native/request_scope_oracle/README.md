# Original request scope and cache lifetime replay

This test-only crate compiles the complete frozen `request_ctx.rs` and exact
`ViewCache` struct/impl, including owned `forget_all`. Complete original sources
are checked before extraction. All 14 registry dependencies match the original
Runtime lockfile versions/checksums. No original Rust is in the production HIA
artifact.

`run.py::run(args, execute_callback=None, environment=None)` makes exactly two
process calls: `request-scope-rust-compile`, timeout 180 seconds, and
`request-scope-rust-compare`, timeout 120 seconds. Arguments are `runtime_root`,
`corpus`, new `output`, `cargo`, optional `rustc`, and optional `offline`.
The callback receives `name, command, timeout, env, input_bytes` and returns a
CompletedProcess with complete raw stdout/stderr. Default build is `--locked`;
offline is optional. Every run creates a new crate and target.

The driver reads every complete native gzip input/stdout/stderr and ordered
domain record. Successful operations become reference inputs. Expected hint and
cache bytes and native reference counts stay outside Rust. Private native lease
IDs label actual Arc objects; reference counts come from the real Arc/Weak.
Malformed, binding and capacity refusals remain a non-Rust domain. The deliberately
preinitialized-context private admission control is also separate from the
original public scope domain.

Two original `with_request_context` futures are polled alternately on one real
Tokio task. Every return from poll verifies that the task-local context is
absent outside that future. Complete/error return, drop and intentional panic
destroy the original scoped future. Weak observes clone counts and final
destruction. The only cache adaptations are admitted UTF-8 keys and access to
original private methods. This focused corpus exercises actual get/set and
owned forget_all; the broader cache-method comparison remains its own suite.

Additional real Tokio tasks verify abort with a cancelled JoinError, spawn
without inheritance, panic with a panic JoinError, and an independently owned
publication worker surviving request cancellation plus session release. The
worker calls original owned forget_all and releases its own Arc. This establishes
the lifetime relation, not an asynchronous stdio writer implementation.

```
python -I -B tests/hia_native/request_scope_oracle/run.py \
  --runtime-root /absolute/runtime --corpus /absolute/native-corpus \
  --output /absolute/new-reference-output \
  --cargo /absolute/cargo --rustc /absolute/rustc
```

Production HTTP concurrency, the final dispatcher route, unbounded cache
storage and original-runtime removal remain unqualified by this focused replay.
