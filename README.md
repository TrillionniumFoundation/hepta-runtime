# Hepta Runtime

Rust owns the MCP server, policy checks, native filesystem and artifact operations,
and durable process lifecycle. Optional document, remote-operator and model routes
also use Python helpers; Ghidra/JADX routes use Java. Those configured engines are
part of their routes even though the primary application is a Rust binary.

## Repository guide

| Area | Purpose |
| --- | --- |
| `src/`, `Cargo.toml`, `Cargo.lock`, `vendor/ruzstd/` | Current Rust crate, embedded Python/Java helpers and patched decoder |
| `deploy/`, `config/`, `workers/weight/` | Deployment assets, configuration and optional model worker |
| `tests/`, `scripts/`, `.github/` | Regressions, independent references and build/release workflows |
| `tools/cloud-compute/` | Colab/Kaggle orchestration and offline tests |
| `tools/x230/20261028`, `20261029`, `20261030`, `a27` | CI qualification harnesses and pinned resource sampler |
| `docs/`, `experiments/`, `qualification/` | Architecture, retained evidence and reproducible research |
| `archives/` | Exact Git history indexes for retired source copies and campaigns |

See [repository layout and language boundaries](docs/REPOSITORY_LAYOUT.md) and
[the cleanup audit](docs/audits/repository-cleanup-20261115/README.md). The complete
pre-cleanup tree remains in Git, with per-file source commit, path, blob and mode
records for every retired file.

## Integration qualification boundary

The source union retains the qualified 124-component behavior profile below.
The imported successor also contains two binary-owner components in its
126-component builder; their complete public route is still explicitly
unregistered. Merging these sources does not extend the older qualification
or activate production. The existing controller and every remaining original
handler stay available until their matching HIA route and recovery gates pass.

## HIA native implementation

The [HIA native profile](native/README.md) provides executable `.hepta` owners
and Linux ELF transport packers. The resulting program runs without Python,
Rust, libc, or a dynamic loader. A pinned Hepta compiler and explicit Python
build and evidence readers produce and verify the executable.

The default native builder assembles **124 HIA components**: 116 directly linked
owners and an eight-component shared worker capability in 117 physical containers.
The graph routes thirteen target handlers: `host_list`, `effective_config`,
`execution_shadow_admit`, `view`, `workdir`, `directory_create`, `file_move`,
`directory_move`, `text_editor`, `batch_edit`, `weight_bellman_plan`,
`extract_lines` and `text_file_write`. The configured catalog advertises eleven
tools, or eight when runtime configuration is absent; Batch and Bellman have
actual routes but remain outside that advertised set. Component counts are
not tool counts.

TextEditor retains shared Local Create/Replace/Delete/Undo owners. The Local
extract and text-file publisher call chains use the actual configuration,
SessionOwner, path-policy, Scope, cache, history and lock owners. Current SDK
connection, metadata admission, get_info, typed text construction, transport
and shutdown stay in the graph. Protocol peer information is not an identity
credential.

The bounded publisher lifecycle qualification includes 22 public SDK scenarios
and eight direct handler-future scenarios on the real two-session pump and
shared process pool. SDK notification cancellation can leave the handler
running through its blocking body and post-await Forget. Direct future Drop
instead follows the original Scope-cancel path and skips that post-await
Forget. EOF drains both session pumps and closes the shared runtime once.
These results establish the declared Local domain, not full SDK concurrency
or Remote execution.

Build and launch the actual default entry with an explicit verified bootstrap:

```sh
python3 -I -B scripts/hia_native_runtime_mcp_build.py   --hepta /absolute/path/to/pinned/Hepta   --bootstrap /absolute/path/to/verified/bootstrap   --output /absolute/path/to/new-public-build
/absolute/path/to/new-public-build/build/public-task-batch-extract/runtime-mcp.elf
```

CI omits `--bootstrap` and freshly compiles all 124 components. The
[current public qualification](native/runtime_mcp_current_qualification.md)
binds all 536 source files and the actual default command. The complete new
publisher regression compares 686 current-native cases with immutable actual
current-Rust captures, including whole wire, file contents, session/cache,
history and locks. All 24 native processes keep their original 180-second
limit, with 60 seconds per exchange. Independent uploaded readers recheck
the complete captures without executing either implementation.

The dedicated [historical 58-image source profile](tests/hia_native/historical_public58/README.md)
restores its exact 120 historical files and excludes current-only sources.
The prior 91-, 102- and 111-component qualifications retain their original
source identities. The old nine-role 111 result is retained evidence for that
graph; it is not relabeled as a 124-component result. The current default
workflow checks the exact candidate or PR head against the qualified
536-source closure, builds that default entry, and requires the resulting
ELF to equal the application-qualified current binary.

The production target has 136 registered tool handlers. The current graph
routes thirteen, leaving **123 unrouted target handlers**. The existing
production runtime continues to own the remaining filesystem, process,
host, SSH, HTTP, document, REA and model-worker behavior.
[The source coverage inventory](native/migration.json) and
[exact target snapshot](native/migration_target.json) retain these gaps.
Full SDK, full asynchronous runtime, full handler replacement, production
activation and removal of the old runtime remain unqualified.

The retained component registry and its eleven native partitions and eight
original comparison partitions remain separately qualified. Their counts
and passing results do not imply coverage of the current public graph.

## Concurrent execution

Independent requests have no Hepta Runtime execution-count ceiling. SSH,
durable-job I/O, search, document and artifact workers, PTYs, model workers,
metadata queries and audit synchronization no longer reserve fixed global or
per-host execution slots. `effective_config` reports
`limits.concurrent_execution: "unbounded_by_runtime"`.

Same-operation reconciliation, shared-store transactions and original-child
cleanup still preserve their owners. Data size and retained-history quotas are
separate from concurrent execution. See [Concurrency policy](docs/CONCURRENCY_POLICY.md)
for the removed gates, preserved invariants and external transport boundaries.

## Native artifact and weight integration

The [unified REA/runtime integration](docs/rea-native/UNIFIED_RUNTIME.md) combines
the native runtime owner and R9/R10 concurrency work with large GGUF/safetensors
directories, bounded tensor reads, ZIP application-container indexes, pinned
GNU analyzers, JADX and versioned Ghidra providers, native JS/TS AST inspection, bounded
Rust CDP browser capture, immutable native weight patches and a scoped Rust F32
Linear forward operator. Each report states its coverage and identity scope.
Native artifact operations work without a resident Python model or Node REA process.
Operator-mode durable jobs retain the existing Python launcher and runner.
Ghidra/JDK and Chrome remain explicit engine dependencies for their routes.

- [Verified native analysis increment and evidence](docs/rea-native/NATIVE_ANALYSIS_INCREMENT_20261104.md)
- [Static providers and original-job lifecycle](docs/rea-native/STATIC_PROVIDERS.md)
- [Versioned Ghidra function analysis and decompilation](docs/rea-native/GHIDRA_ANALYSIS.md)
- [Native JavaScript/TypeScript and Electron AST observations](docs/rea-native/JAVASCRIPT_AST.md)
- [Local browser capture through the existing job owner](docs/rea-native/LOCAL_BROWSER_CAPTURE.md)
- [Exact native weight artifacts and restoration](docs/weight-runtime/NATIVE_ARTIFACTS.md)
- [Native F32 Linear calculation and independent comparison](docs/weight-runtime/NATIVE_LINEAR.md)
- [Native semantic replay joined to exact continuation certificates](docs/weight-semantic-certificate.md)

The [frozen REA 6.8.0 compatibility ledger](docs/rea-native/compatibility/README.md)
tracks all 229 upstream tools, their implementation scope and remaining behavior
gates. CI checks its source bindings and mapping consistency; complete upstream
behavioral parity remains OPEN.

Use the CI's isolated runner for the full runtime suite:
`cargo nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast`.
Some historical tests intentionally modify process-global state and require
separate processes. The pinned toolchain, CI gates, and manual Linux artifact
packaging are documented in [CI and private release validation](.agents/release.md).

## Weight-space research workbench

The optional `hepta-weight` domain runs a resident CPU model under the existing
process owner. It supports internal probes, temporary causal interventions,
bounded numerical analysis and exact typed weight patches. Candidate artifacts
retain base/backend identity, realized dtype changes and costs.

- [Enable profiles and use the six MCP tools](docs/weight-runtime/RUST_OWNER.md)
- [Compose probes, SVD and writer-column edits](docs/weight-runtime/ANALYSIS.md)
- [Python worker protocol and model adapters](workers/weight/PROTOCOL.md)
- [Implementation qualification and closed defects](docs/weight-runtime/QUALIFICATION.md)
- [Separate frozen paired evaluation](experiments/weight/evaluation/README.md)
- [Public MIT Qwen reconstruction and measured mechanism replay](experiments/weight/mit_replay/README.md)

Profiles default to disabled. The research worker does not train, replace an
active checkpoint, grant production eligibility, or place an order. Confirmation
outcomes and production selection remain with their existing independent owners.


**Current capabilities:** [CHECKPOINT_LIFECYCLE.md](docs/CHECKPOINT_LIFECYCLE.md) describes the native, pinned Linux checkpoint API with bounded thread groups and separate stopped-restore/resume actions. [PROTECTED_AND_COMPLEX_PARITY.md](docs/PROTECTED_AND_COMPLEX_PARITY.md) covers native protected PDFs, explicit certificate anchors, complex workbooks and inode-preserving patches. Earlier failed/withdrawn experiments remain historical evidence, not the status of the current implementation; exact installation is established by its dated receipt.
Policy-enforced, multi-host MCP runtime for durable process execution, interactive PTYs, read-only hardware/service/network inspection, and exact administrator-approved privileged actions.

This project is derived from [Muvon/octofs](https://github.com/Muvon/octofs) at commit `37b5d3d02be511bae86d91fa980996a5fe257d7b` under Apache-2.0. See the [original Octofs documentation](https://github.com/Muvon/octofs/blob/37b5d3d02be511bae86d91fa980996a5fe257d7b/README.md) for upstream reference and [`docs/HEPTA_RUNTIME.md`](docs/HEPTA_RUNTIME.md) for the fork-specific architecture, policy, deployment, and recovery contract.

## Hepta operator deployment

The optional [two-phase process checkpoint API](docs/CHECKPOINT_LIFECYCLE.md) separates memory restoration from explicitly authorized execution; host capability pins remain opt-in.

See [local handoff, restart and format completion](docs/LOCAL_HANDOFF_AND_FORMATS.md) for the current maintenance and parser capabilities, qualified scopes, and local native CLI.

See [native binary/remote document/page/range tools](docs/NATIVE_TRANSFER.md) for the current local replacement APIs and their explicit preservation limits.

See [the v5 native DC-replacement candidate](docs/DC_FUNCTIONAL_V5_NATIVE_CANDIDATE.md) for bounded multi-file UTF-8 reads, configured-host SSH health and durable cancellable search. The [optimized six-host stage receipt](docs/qualification/dc-functional-v5-release-staged-20261013.json) records a staged artifact, not an installed catalog or full replacement. The installed v4 service and Desktop Commander remain active; [the Work handoff](docs/WORK_HANDOFF_DC_REPLACEMENT_20261013.md) lists caller/resume, model-origin, business and recovery/cutover gates.

Current bounded metadata/configuration candidate: [native v6 audit and configuration](docs/DC_FUNCTIONAL_V6_METADATA_CANDIDATE.md). Installed v4 and Desktop Commander remain unchanged; native receipts do not grant full replacement qualification.
Bounded request cancellation: [native v6 facade candidate](docs/DC_FUNCTIONAL_V6_FACADE_CANCELLATION.md), with actual six-host native/facade receipts; ChatGPT model-origin and production cutover remain open.




The upstream Octofs packages do **not** install this fork. Build Hepta with `cargo build --release --locked --bin hepta-runtime` and use the configuration and deployment assets in this repository.

For trusted-account shell, external-PID signalling and temporary sudo, see [Operator mode](docs/OPERATOR_MODE.md). For complete operator output archives and target-owned terminals that survive controller restarts, see [Persistent terminals](docs/PERSISTENT_TERMINALS.md). The isolated default remains separate; arbitrary operator execution is not a sandbox.

Follow the exact source/binary qualification receipts under `docs/qualification/`. Source implementation, a parallel installed service, and a completed Desktop Commander cutover are different states. Preserve DC for existing sessions and rescue; cloud/ChatGPT registration is the final, separately authorized step.

## Durable inventory pagination

`process_list_page` observes the complete private job registry before returning
its first page. Continue the returned opaque cursor with the same host filter;
page limits are independently selectable from 1 to 128, with a 64 KiB response
bound. Only the final page has `inventory_complete: true`. Job metadata remains
an observation; use `process_status` for authoritative live status.

The controller prunes idle snapshots toward a four-entry cache target and
accounts for at most 32 MiB of owned snapshot payload. The entry-count target
does not refuse additional active readers. Cursors expire five minutes after
the observation; expired idle entries are removed on subsequent access.
In-flight entries remain charged until their readers finish. Independent scans
and render operations have no fixed worker admission ceiling, including cold
observations not yet published in the cache. A continuation is bound to its original state root,
host filter and controller-local handle. Expiry, eviction, restart or a detected
source change requires a fresh first page. A fresh first page always rechecks
the source; it cannot silently resume an older observation.

Every continuation reads and hashes all original receipt bytes on every host.
The cache reuses the checked public projection and digest. Filesystem timestamps
and directory content watches do not prove unchanged content; in particular,
Linux inotify does not report writes through an existing shared memory mapping. The source limits remain 65,536 records, 128 MiB,
4 MiB + 64 KiB per record and five seconds; a refusal returns no partial inventory.
This source candidate still requires dev-host tests and an exact-build Mac
measurement before it qualifies the observed 1,912-record production workload.

## Native library builds

The default `remote-fs` feature includes the existing SSH/SFTP filesystem backend.
The `hepta-runtime` CLI requires this feature, so its default build and host-key
verification remain unchanged. A trusted native process consumer can depend on
the library with `default-features = false` to omit `russh` and `russh-sftp`.

Without `remote-fs`, local filesystem access and the existing native durable job
owner, original-request reconciliation, policy checks, and system-SSH process
transport remain available. All remote filesystem APIs reject `ssh://` and
`sftp://` operations, including the runtime's descriptor-relative file helper;
they do not interpret those URLs as local paths. The `native` API still requires
the embedding host to validate final-use authorization independently.

`native::execute_or_observe_with_entry` accepts an owned `Send + 'static`
callback and guard. Move the host's owned capability into the callback; the
independent transport owner invokes it immediately before the original SSH
spawn and retains its guard until that original child is reaped, including
after caller cancellation. Reusing an existing binding only observes it and
does not consume the callback or submit another launch.

## Development

For this Hepta checkout, use the pinned Rust toolchain and isolated test runner:

```bash
# Install CI tool versions
rustup toolchain install 1.95.0 --profile minimal --component rustfmt --component clippy
cargo +1.95.0 install --locked --version '=0.9.137' cargo-nextest

# Build both runtime binaries
cargo +1.95.0 build --locked --release

# Run tests
cargo +1.95.0 nextest run --locked --all-targets --all-features \
  --test-threads 1 --retries 0 --no-fail-fast

# Lint (zero warnings policy)
cargo +1.95.0 clippy --locked --all-targets --all-features -- -D warnings

# Format
cargo +1.95.0 fmt --all

# Run locally
cargo +1.95.0 run --locked --bin hepta-runtime -- mcp
```

### Running Tests

```bash
# Library configuration without remote filesystem support
cargo +1.95.0 nextest run --locked --all-targets --no-default-features \
  --test-threads 1 --retries 0 --no-fail-fast

# Specific tests, still isolated by process
cargo +1.95.0 nextest run --locked --all-targets --all-features \
  --test-threads 1 --retries 0 -E 'test(test_view_file)'

# Include output from successful tests
cargo +1.95.0 nextest run --locked --all-targets --all-features \
  --test-threads 1 --retries 0 --no-fail-fast --success-output immediate
```

## Distribution and standalone bridge

Build from a Git checkout so Cargo uses the checked-in `vendor/ruzstd` decoder
patch. The supported Linux artifact is produced by the manual private-release
workflow in [CI and private release validation](.agents/release.md). Ordinary
registry packaging omits the root patch and nested crate, so its file list is
not a supported release contract. Historical retirement reduces that file list
without changing Cargo metadata or the private-release deployment payload.

For a standalone read-only MCP bridge, copy
[`deploy/readonly-bridge/bridge.py`](deploy/readonly-bridge/bridge.py). The existing
`deploy/chatgpt_mcp_bridge.py` checkout entry delegates to that implementation.
Its stdio/HTTP API and the installed standalone service path are unchanged.

## Contributing, security and license

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and the
[Apache-2.0 license](LICENSE). Original Muvon copyright notices remain in derived
source. Upstream package names, installation commands and badges belong to
[Octofs at the imported revision](https://github.com/Muvon/octofs/blob/37b5d3d02be511bae86d91fa980996a5fe257d7b/README.md).
