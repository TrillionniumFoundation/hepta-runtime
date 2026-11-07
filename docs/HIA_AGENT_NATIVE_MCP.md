# HIA Agent-native tools in hepta-runtime

The optional `hia_worker` configuration registers eleven HIA tools in the actual
Rust MCP router. The worker emits x86-64 machine code and ELF objects through
Hepta's direct backend. The Agent selects program changes and explicit machine
plans; the adapter runs no profitability optimizer and offers no compiler or
assembler fallback.

The tool family is disabled unless an administrator configures a pinned worker.
The source contract is `src/mcp/hia_tool_catalog.json`. `tools/list` preserves its
input and output schemas, including nullable references and conditional claims.
Both requests and complete worker reports are checked against that contract.

## Installation and authority

Install the Hepta direct-backend/tool-service candidate on an already configured
Linux execution host. The Python environment must include the dependencies of
that Hepta candidate. With that installation as the current directory, obtain
its actual pins:

```sh
python3 -B -E -s -m hepta.hia_agent_worker --installation-manifest
```

Merge the `hia_worker` object from `config/hia-worker.example.json` into the
existing runtime configuration and replace its host, paths and pins. Its host
must already exist in `hosts`; caller arguments cannot supply an SSH destination,
interpreter, source root, store root or environment. The installation and artifact
capture roots must fit that host's read policy. The private state root requires
read/write authorization and must be disjoint from the source installation.

The worker pin is SHA-256 of canonical compact UTF-8 JSON mapping each sorted
`hepta/**/*.py`, `docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json`,
`docs/HIA_AGENT_ASSEMBLY.md` and `docs/HIA_PROGRAM.md` relative path to the
SHA-256 of its bytes. The backend and catalog have separate identities. The
adapter passes all three expected pins on fixed argv; the worker checks them
before creating writable service state and reports actual installed hashes.
This binds the installed Python source. It does not attest the Python executable,
OS, linker, system libraries or hardware firmware.

The state root belongs to the configured operator authority and persists across
its sessions. It is not per-ChatGPT-user isolation. HTTP credentials and native
session admission remain the existing runtime's responsibility. Returned artifact
digests and context references do not create execution permission.

Start the existing server normally:

```sh
hepta-runtime mcp --runtime-config /path/to/reviewed-runtime.json
```

The usual authenticated streamable HTTP transport also exposes the same router.
No separate HIA scheduler, HTTP server or command endpoint is introduced.

## Discovery and use

Call `hia_describe` with `{"section":"manifest"}`. Read its returned resources
with `hia_read`, or use `resources/read` with the exact issued `hia://` URI.
The remaining tools are `hia_artifact`, `hia_context`, `hia_inspect`,
`hia_candidate`, `hia_verify`, `hia_emit`, `hia_evaluate`, `hia_adopt` and
`hia_rollback`. The catalog supplies their exact arguments and result shapes.

`hia_artifact` accepts bounded UTF-8 text. Path capture accepts an absolute path
on the configured worker, or the corresponding registered SSH URI. It uses the
runtime path resolver and refuses foreign hosts, explicit user/port overrides,
relative controller paths, traversal and paths outside the worker artifact roots.
The worker captures a bounded stable regular-file snapshot. No caller path is
used as an executable or output location.

`hia_emit` specifically calls the direct backend. The legacy Hepta CLI `hia emit`
command is a different command and is not used by this integration. Object
emission, optional linking, native evaluation and adoption have distinct receipts.
Core admission, behavioral equivalence, lowering validation, encoding checks and
measured benefit remain separate claims. Unsupported proof domains stay explicit.

## Durable execution and recovery

Every call is submitted to the existing native process owner with fixed argv and
bounded JSON stdin. Mutation identity binds the tool and caller's `request_key`;
changing payload or installation under that same key conflicts with the existing
owner binding. Read-only calls use a stable digest of their complete arguments and
profile. Original path spelling is additionally bound before normalization.

The adapter first observes the original request. For a new request it uses
`native::execute_or_observe_with_entry`, whose locked owner path never relaunches
an already bound uncertain job, including a concurrent first-call race. The
existing process-group supervisor owns timeout, logs and cancellation.

An initial response may have `status: "accepted"` with its original host/job
identity. Repeat the same HIA tool and unchanged arguments to observe that job and
receive the typed terminal result. `process_status`, `process_read`,
`process_wait` and `process_cancel` remain available through the runtime. A raw
exit code or stdout read is not a validated HIA result.

A terminal result requires the native owner's durable complete-output witness
and a report matching tool, canonical request, profile, source bundle, backend
and catalog. The adapter also checks result subjects and actual output schema.
Missing, truncated, changed or failed worker reports produce `unknown` with the
original operation. Cancellation acknowledgement is not completion. A protocol
error before a job identity can be recovered tells the caller to retain the tool,
request key and arguments; it does not authorize a replacement execution.

`resources/read` uses the same owner and typed validation with a private URI lookup
operation. A pending resource read returns the original operation in error data;
repeat the same URI or use `hia_read`. Resource text is a bounded JSON page with
artifact identity, encoding, content and continuation cursor. Pagination uses
`hia_read` with the original immutable reference.

## Catalog consumers and qualification

`deploy/contracts/hepta-hia-agent-native-v1.json` is the explicit eleven-tool
family contract, with every operation annotation and both schemas preserved.
Regenerate and compare it to a captured actual `tools/list` response with:

```sh
python3 deploy/hia_mcp_catalog.py \
  --native-tools /path/to/actual-tools-list.json \
  --output deploy/contracts/hepta-hia-agent-native-v1.json
```

The existing private full-operator facade verifies its entire upstream tool list;
its deployment must pin the complete catalog of the configured server. The
HIA-only family contract is not a replacement for that whole-server pin. The
separate public gateway's reviewed v4 policy is not changed by this source
integration. Adding this file does not deploy a service or change a gateway's
allowlist.

Regression coverage includes argument/subject constraints, u64 generations,
unchanged-request ownership, changed-source conflicts, root and host admission,
report forgery and omitted-output rejection, native-only emission flags, and the
serialized size of maximally escaped read pages. Runtime build/lint/test results
and actual SSH/MCP lifecycle evidence belong to the accompanying qualification
record; source registration alone does not assert those results.
