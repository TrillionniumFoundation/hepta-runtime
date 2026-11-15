# Weight experiment MCP owner integration

The six weight tools coordinate a resident model worker through the existing
`runtime::jobs` authority. They do not introduce another process supervisor,
install dependencies, train a model or promote a candidate. A successful process
or sealed research artifact is not an evaluation pass.

## Administrator configuration

The existing runtime JSON gains a default-empty `weight_workers` map. When empty,
the six tools are absent from discovery. Each profile refers to an existing host
with execution and write permission. The worker/input/session paths must remain
inside that host's read/write/cwd policy. The session root must already exist; its
length plus 40 bytes cannot exceed 103 bytes because it contains a Unix socket.
This version qualifies weight profiles on Linux controllers; configurations without
weight profiles retain the existing runtime platform behavior.

Example profile, to merge into an existing runtime configuration:

```json
{
  "weight_workers": {
    "research_cpu": {
      "host": "configured-worker-host",
      "python_executable": "/opt/weight-env/bin/python",
      "worker_path": "/opt/hepta-runtime/workers/weight/worker.py",
      "worker_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_DIGITS",
      "worker_package_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_DIGITS",
      "session_root": "/var/lib/hepta-weight/sessions",
      "input_roots": ["/srv/research-models"],
      "allowed_providers": ["torch_sequential"],
      "max_memory_bytes": 4294967296,
      "max_cpu_threads": 2,
      "max_lifetime_seconds": 1800,
      "max_request_ms": 120000,
      "max_active_sessions": 1,
      "max_requests_per_session": 128
    }
  }
}
```

Replace paths, host alias and pins with independently admitted installation values.
The admitted worker's `--print-identity` prints entry/package hashes. The package
pin covers the entry and runtime Python modules; entry pinning alone does not bind
imports. These hashes detect code drift, not cryptographic publisher signatures.
Callers cannot replace interpreter, host, worker, input roots or output root.
The Python environment is provisioned before startup, and model loading is offline.
The existing host network/fallback policy is preserved without relaxation.

### Optional native Rust client

To use Rust for each socket exchange, add the following object to an admitted
worker profile, with the executable and digest of the installed binary **on that
profile's worker host**:

```json
{
  "native_client": {
    "executable": "/opt/hepta-runtime/bin/hepta-runtime",
    "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_DIGITS"
  }
}
```

The executable must be inside the host's configured read paths and outside its
protected paths. There is no fallback to the controller's executable path. The
binary must contain the hidden `weight-client` subcommand. A missing installation,
wrong pin or unsupported invocation fails its original durable job; it does not
silently invoke Python or select another host.

Omitting `native_client` retains the existing Python client and historical profile
serialization, including previously recorded profile digests. Enabling or changing
it changes the profile digest and requires a new experiment admission; existing
session status/read/close still refer to the original jobs. The resident model
worker remains the same pinned Python/PyTorch process in both modes.

The Rust client verifies its running executable identity (`/proc/self/exe` on
Linux), the worker entry hash and the configured package hash before connecting.
Package identity uses the existing Python canonical string dictionary, computed
in Rust with streaming file hashes. Package source is bounded to 32 MiB and 256
files, including the entry. The executable hash is streamed with a 2 GiB byte cap;
no executable or model is loaded into one whole-file buffer.

One request and one response pass through as exact bytes, including numerical
spelling. Validation rejects duplicate JSON members, wrong session/request IDs,
incomplete or multiple JSONL frames and invalid result/error envelopes. Requests
retain the admission bound (64 KiB plus the newline); responses are at most 1 MiB
including the newline. Native peers require a private, same-UID Unix socket.

Only connection establishment may wait/retry before any request bytes are sent.
After a possible send, timeouts become `REQUEST_TIMEOUT_UNKNOWN`; transport or
protocol failure records an unknown operation state. The client never reconnects
or resends that operation. Inspect the original job and its retained worker
operation before any new experiment. These are transport receipts, not evidence
that a model computation was rolled back.

Native jobs use one Tokio worker thread. The original job owner retains process,
resource, cancellation and log ownership; the native client has no second job
registry. Its owner deadline includes bounded stdin admission, code verification
and socket connection, as well as the exchange timeout.

## Tool workflow

| Tool | Result and ownership |
| --- | --- |
| `weight_profiles` | Enabled profiles, providers, code hashes and resource ceilings |
| `weight_open` | Stable session and original resident process job reference |
| `weight_call` | Original bounded client job reference for a typed worker operation |
| `weight_status` | Existing owner's lifecycle observation, optionally waiting up to 30 seconds |
| `weight_read` | Existing owner's stdout/stderr pages with independent byte cursors |
| `weight_close` | Closes admission and requests cancellation of the original resident job |

Open uses `{profile, idempotency_key, params}`. `params` contains the provider/model
schema from `workers/weight/PROTOCOL.md`; Rust injects policy-owned paths and limits.
Retain the returned `session_id` and `job_id`. Admission does not mean model loading
has completed: read the startup worker result through `weight_read` with that
session and no `request_id` (or `request_id: "open"`).

Calls use `{session_id, request_id, op, params}`. Registered operations are
`inspect`, `probe`, `intervene`, `analyze`, `patch`, `seal` and `query`. The
`weight_call` result is a job receipt. Read its worker JSON with `weight_read` and
the same request ID; inspect `ok` and the typed result/error. Requests are limited
to 64 KiB at MCP admission. Large arrays stay in artifacts; `query` pages values.
No call evaluates arbitrary caller-supplied Python.

After uncertainty, reuse the exact same open key or call ID and semantic parameters.
Open resolves the original worker job; calls resolve the original client job.
Changed content under an existing identity is rejected. Changing an ID to retry
an uncertain effect defeats this contract; unresolved worker operations are held.

Close records that no more calls may be admitted and requests cancellation of the
stored resident job. Confirm its terminal state with `weight_status`. The close
receipt does not claim termination has already occurred. Evidence remains, and a
closed identity cannot launch another worker. A new experiment uses a new identity
and the normal capacity gate. Process success and model quality are separate facts.

## Durable state and budgets

`state_dir/weight-sessions-v1` is a private coordination index. Create-only records
bind exact requests, profile, code pins and original host/job identity. SHA-256
payload checks, private regular files, no-follow reads, atomic publication and
directory synchronization reject corruption and conflicts. A bounded Unix flock
serializes cooperating controllers. Execution, status, cancellation and log capture
remain in `runtime::jobs`.

An unresolved admission holds a session lease until the original owner can be
reconciled; unknown processes do not count as free capacity. Call intents reserve
budget before any possible effect. The index is capped at 64 MiB and 1024 sessions;
full storage needs administrator archival, not automatic evidence deletion. New
effects require the current profile hash to match the recorded profile. Historical
status/read/close use the recorded original binding.

The existing owner enforces resident CPU/memory/deadline budgets. The worker adds
request, idle, lifetime, forward-example, patch and artifact limits. Each call
launches the configured Rust client or compatible standard-library-only Python
client under the same owner, then exchanges one
request with the resident mode-0600, same-UID Unix socket. A client does not reload
the model. Hard timeouts retain unresolved operation records rather than replaying
computation.

## Qualification

Rust unit tests cover path/pin/budget policy, stable identities, the fixed owner
process contract, typed bounded requests, immutable records, tampering, symlinks
and controller serialization. The real external test additionally uses a synthetic
2×2 safetensors file, actual stdio MCP binary, SSH process owner, resident PyTorch
worker and Unix-socket clients:

```text
HEPTA_WEIGHT_REAL_SSH=1 \
HEPTA_WEIGHT_TEST_PYTHON=/absolute/cpu-env/bin/python \
HEPTA_WEIGHT_TEST_WORKER=/absolute/checkout/workers/weight/worker.py \
cargo test --locked --all-features --test weight_mcp_external -- --ignored --nocapture
```

It requires an existing authorized localhost SSH identity. Both the Python
compatibility test and the native client test must be explicitly executed; each
prints its `client_transport` in the qualification receipt. They check discovery,
open, controller restart/original job reuse, same-ID reuse, changed-content
rejection, real probe/query, active-session admission, close/terminal observation
and unchanged source weights. Ordinary `cargo test --all-features` ignores this
external tests; that is not an owned-host success receipt. Registering production
selection or trading behavior requires a separate reviewed owner integration and
independent evaluation; these tools do not grant one.
