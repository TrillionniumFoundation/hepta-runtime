# JS/TS/Electron native AST qualification — 2026-11-04

This receipt qualifies the bounded `rea_inspect_javascript_graph` implementation
on the recorded Linux host. The shipped Rust runtime parses explicitly selected
JS/TS/JSX/TSX source text with Oxc 0.144.0, retains imports/exports and lexical
Electron callsites, and forms literal-channel candidate edges. Node and Babel
are independent development oracles, not production execution dependencies.

**Final qualification: PASS**, subject to the scope below. It does not establish
full REA 6.8.0 tool parity, a complete application graph or live Electron IPC.

## Qualified build

| Item | Recorded value |
| --- | --- |
| Source base | `310add6db47bcfbed3545432eb528a72f5eb6dcd` plus the recorded unstaged source manifest |
| Runtime binary SHA-256 | `c54b97b6cb9eb5b65e900f047e8aa565ed4dba562604a102f513097eab5beb42` |
| Full source manifest SHA-256 | `ca4a45451601a75164ca8a6494e86f2693d60b608ebf9f0fa1885e0f8958911c` (uncompressed JSON bytes) |
| Manifest entries | `8250` |
| Build target directory | `/home/qian-qi/work/hepta-rea-next-javascript-20261104-target` |
| Build environment | `CARGO_BUILD_JOBS=4`; `CARGO_TARGET_DIR` as above |
| Rust/Cargo | Rust 1.95.0 / Cargo 1.95.0, `x86_64-unknown-linux-gnu` |
| Profile | Normal `dev` production binary; opt-level 1, debuginfo 2, codegen-units 256, debug assertions enabled |

`build-environment-v5.json` records the actual rustc path, options and selected
environment fields observed from compiler processes. `RUSTFLAGS`, encoded
Rust flags, compiler wrappers and profile override variables were absent. Test
builds unify rmcp's client development feature; the normal binary was restored
with `cargo build --locked --all-features --bin hepta-runtime -j4` before the
integration executable invoked its `CARGO_BIN_EXE_hepta-runtime` path.

The complete repository file manifest was checked before and after executing
qualification, and the runtime binary hash was checked around the actual MCP
and final Babel runs. The qualification output directory was added after those
checks; it is not included recursively in its own source manifest. These
receipts qualify this source snapshot and binary, not a later combined build.

## Gates actually executed

| Gate | Result and concrete scope |
| --- | --- |
| Native units | 7 passed, 0 failed; selected graph/parser/admission tests. The other library tests were compiled but filtered from this run. |
| Actual stdio MCP | 1 passed, 0 failed; package declaration → explicit-source graph, tool discovery, bounded worker, independent imports/bindings, two controller starts, continuation binding, stale source refusal, outside/symlink refusal, malformed/oversized input, AST node budget refusal, and recovery. |
| Source execution marker | The actual MCP fixture points `writeFileSync` at a writable temporary marker path; the marker remained absent. |
| Independent Babel comparison | 17 import observations/bindings, 16 export observations, 12 Electron callsites, and 4 IPC candidate edges matched the actual Rust worker. |
| Manual export golden | Both Babel and Rust matched eight per-file export counts and the three manually enumerated corrected observations. |
| Formatting | `cargo fmt --all --check` exited 0. |
| Lint | `cargo clippy --locked --all-features --all-targets -j4 -- -D warnings` exited 0. |

The final commands, durations, executable hashes, log hashes and results are in
`qualification-v6.json`; full output is retained in the adjacent logs. No full
repository test-suite execution or production deployment is asserted here.

## Independent-oracle correction, retained without changing production AST code

The first Babel comparison genuinely failed: its export extractor produced 14
observations while Rust produced 16. The import, Electron-call and IPC-edge
comparisons already agreed. `reference-v3.json` and the old extractor preserve
that result, including the one missing default-name observation and three
extra observations in the Rust-normalized set.

The cause was in the reference extractor: Babel's generic value-binding helper
does not enumerate these TypeScript-only declaration IDs, and the initial
extractor assigned every default expression the synthetic `*default*` name.
The corrected extractor reads the relevant Babel AST fields directly. The
authored source supplies independently countable expectations:

| Authored source | Babel raw node and UTF-8 byte span | Expected observation |
| --- | --- | --- |
| `export interface Payload { key: string; value: number; }` | `TSInterfaceDeclaration`, `id.name=Payload`, declaration span `[0,56)` in `src/types.ts` | Exported/local syntactic name `Payload`, type-only |
| `export type Name = string;` | `TSTypeAliasDeclaration`, `id.name=Name`, declaration span `[57,83)` in `src/types.ts` | Exported/local syntactic name `Name`, type-only |
| `export default answer;` | `ExportDefaultDeclaration` with `Identifier(name=answer)`, span `[69,91)` in `src/util.js` | Exported name `default`; local syntactic name hint `answer` |

The last row does **not** equate an expression operand with an ECMAScript live
export binding. `local_name` in this inventory is a syntactic name hint. Default
expression evaluation, snapshot/live-binding behavior and module instantiation
are unobserved. Full raw Babel nodes and source excerpts are preserved in both
the corrected reference and final reference. The manual golden is checked
against each implementation independently.

`oracle-extractor-correction-v4.json` records the before/after extractor hashes.
The Oxc AST implementation did not change during this correction. The final
reference records the extractor hash and exact npm lock hash; the oracle's
package manifest and lock are included for reproduction.

## Real MCP transport failure and minimal production fix

Passing the direct-stdin Babel comparison did not prove the controller's MCP
transport. The first actual MCP graph call failed after 20 seconds: the write
future only invoked `shutdown()` on a borrowed Tokio child stdin handle, so the
Unix pipe remained open while the worker waited for EOF.

The locked Tokio 1.53.1 implementation delegates `ChildStdin::poll_shutdown` to
Unix `ChildStdio::poll_shutdown`, which returns success without closing that
pipe. `eof-owner-reproduction-v4.json` records both installed source paths,
their hashes, the relevant code excerpts and a minimal single-call reproduction.
Owner PID 250715 remained alive when the timeout error returned; observed worker
PID 250743 was absent and the owner's children list was empty. This establishes
reaping by the original owner before its later shutdown, rather than relying
on a new controller or job supervisor to remove an orphan.

The production fix gives the write future ownership of stdin (`async move`)
and explicitly drops the write endpoint after sending the request. The transport correction changed only
`src/mcp/rea_javascript_graph_worker.rs` in production. `eof-fix-v5.json` preserves both source hashes and the original
worker file. Source was frozen again before rebuilding, and the native units,
complete owned MCP test and final Babel comparison were rerun on the fixed
binary. The failed MCP receipt and log remain in this directory.

## AST node-store failure and explicit budget enforcement

The next complete MCP run reached the node-budget regression after the preceding
transport, graph, identity and denial assertions. That regression correctly
failed: the source containing 100,001 numeric expression statements was accepted.
The actual Oxc 0.144 default leaves `Semantic::nodes` empty unless
`with_build_nodes(true)` is selected. A separate minimal native probe of valid
source `0;` recorded `ast_nodes=0`; the receipt includes the installed builder
source path, SHA and its explicit default-setting documentation.

The production correction enables the full node store, so the existing 200,000
node limit and reported counts apply to real nodes. The native unit regression
now requires a nonzero count for a nonempty AST and a specific node-limit refusal
for the dense source; the MCP regression also requires the node-limit diagnostic.
The earlier MCP failure and zero-node probe are retained. The final source
identity distinguishes the two production corrections (worker stdin ownership
and AST node-store configuration) from validation-script and test changes.

## Worker isolation: verified code facts and limits

The controller launches its own executable with `env_clear()`, working directory
`/`, three newly piped standard streams and the single hidden subcommand
`rea-javascript-worker`. Original physical source paths, runtime configuration
and controller environment credentials are not supplied in worker argv or
environment. The worker receives copied source bytes and logical IDs on stdin.

Unix resource limits are address space 768 MiB, CPU 12 seconds, open descriptors
64, core size zero and file size 1 MiB. The controller enforces a 20-second
deadline, a 32 MiB request cap, a 1 MiB response plus newline and a 64 KiB stderr
cap. Failure and timeout paths kill and await the worker. Linux additionally
sets a parent-death signal and checks the parent PID around setup.

After stdin is read and before JSON/AST parsing, the existing `rea_seccomp`
mechanism sets `no_new_privs` and installs a thread-synchronized syscall denylist.
It refuses file opens, new sockets/connections, process execution/cloning,
ptrace, io_uring and the other listed cross-process operations. This is the
existing runtime mechanism, not a newly claimed complete sandbox.

There is **no explicit `close_range` sweep** in this worker's spawn path.
Additional descriptors depend on their `FD_CLOEXEC` flags; `RLIMIT_NOFILE=64`
does not close descriptors that already exist. This receipt therefore does not
claim that only descriptors 0/1/2 can survive exec or that inherited credential
descriptors are categorically excluded. UID, mount/network namespaces and all
information-flow channels are not isolated by this boundary. On non-Linux Unix
the shared seccomp helper does not install a filter; non-Unix worker execution
is refused. The functional qualification here is Linux only.

## Semantic scope

Source selection is explicit and bounded. Import targets are selected logical
path candidates, not Node/TypeScript/bundler resolution. Reassigned or shadowed
bindings are excluded from lexical receiver inference. Dynamic expressions
stay unknown. Matching literal channels and API roles produce candidate edges
with `runtime_observed=false` and `process_pair_proven=false`.

No package script, dependency, JavaScript callback, Electron process, ASAR,
source map, preload expression or URL is executed or followed. General dataflow,
property mutation, eval/factories, reachability, process pairing, sender checks,
payload compatibility and successful IPC delivery remain outside this scope.
The native record explicitly reports `complete_application_graph=false` and
`rea_evidence_compatible=false`. See `docs/rea-native/JAVASCRIPT_AST.md` for the
tool schema, limits, paging identity and usage examples.

## Reuse with a combined release binary

The integration executable accepts absolute overrides before it starts the MCP
server. The actual server still receives an empty environment. Use the executable
path recorded in `test-artifacts-v6.json` and point it at the final combined binary:

```sh
HEPTA_JS_AST_TEST_RUNTIME=/absolute/combined/release/hepta-runtime \
HEPTA_JS_AST_FIXTURE_DIR=/absolute/combined/tests/fixtures/rea_javascript \
/absolute/path/to/rea_javascript_graph_external-test-executable --test-threads=1

node scripts/rea-javascript-ast-reference.mjs \
  tests/fixtures/rea_javascript /absolute/path/to/locked-oracle \
  /absolute/combined/release/hepta-runtime /absolute/output/reference.json
```

The Babel script invokes the supplied binary
`rea-javascript-worker` entrypoint directly over stdin. The MCP integration
invokes that same binary through the registered tool and its parent worker
transport. A new combined binary requires its own resulting receipts.

## Packaging details

The source manifests are preserved as complete uncompressed JSON. Compiler
artifact streams are gzip-compressed with deterministic headers. Edit-fix
receipts describe the immediately written text before rustfmt; the final
post-format source manifest is the authoritative build-input identity.
`worker-isolation.json` separates source-reviewed isolation facts from
unqualified descriptor/namespace channels. Target allocation is recorded in
`target-size-after-qualification.txt`; peak disk allocation was not sampled.
After qualification no build, test or other target mutation was run.
