# Frozen REA 6.8.0 Python helper migration inventory

Date: 2026-11-05. Status: **OPEN**.

This inventory identifies **13 shipped Python files and 3 generated or inline Python helpers** in the fixed `rea-agents@6.8.0` package. Against the clean Rust source snapshot below, **0 are fully covered, 1 has a concrete partial overlap, and 15 have no corresponding Rust helper/adapter**. These counts describe this Python inventory only; they are not a score for every dynamic-device capability.

The sole partial row is the native ELF structure preview versus the original pwntools layout implementation. Its schema, completeness and operation boundary differ. It does not qualify `inspect_binary_layout` as replaced.

This is a read-only source inventory, not an execution or equivalence qualification. Tests, mocks, capability declarations, an engine name in an Evidence enum, and generic process launch do not establish a migrated helper. Final real-engine qualification must identify its own exact source and binary.

## Frozen identities

| Component | Identity |
| --- | --- |
| Reference | `rea-agents@6.8.0` |
| Recorded source commit | `93b8b82db70279e40f484114cff9dc1958dc14ee` |
| Reference package root | `/home/qian-qi/work/hepta-rea-reference-20261103/install/node_modules/rea-agents` |
| Packed release | `/home/qian-qi/work/hepta-rea-reference-20261103/pack/rea-agents-6.8.0.tgz` |
| Tarball SHA-256 | `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb` |
| Tarball bytes | 9944902 |
| Package metadata SHA-256 | `b0fc212f6bea9b4ee6e2b3ab0b52dd95402c229da3b8652127e5f131c3445b39` |
| Compared Rust source | `4bc561f36afe47f549c34b68871f532d75ec3620` |
| Rust tree | `/home/qian-qi/work/hepta-rea-sixpack-ca464-20261105` |
| Working tree at inspection | Clean |
| Complete machine-readable ledger | [PYTHON_HELPER_MIGRATION_20261105.json](PYTHON_HELPER_MIGRATION_20261105.json) |

The JSON ledger also records exact hashes for the relevant canonical JavaScript callers, bundled MCP/CLI call sites and Rust source files. The comparison snapshot precedes final binary qualification; later source or binary results must not silently inherit this snapshot's identity.

## Classification

| State | Required meaning |
| --- | --- |
| Covered | The helper's behavior and original integration are implemented in Rust and qualified for identities, failures, limits, cancellation and recovery. |
| Partial | A concrete production Rust entry implements a demonstrable subset. Missing behavior and the original incompatible contract remain explicit. |
| Missing | No corresponding production Rust helper/adapter exists in the inspected source. General ownership infrastructure or unrelated observations are not a port. |

## Shipped Python files: exact source identities

Paths below are relative to the fixed reference package root.

| ID | Path | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| P01 | `bridge/native/rea_lldb_tracer.py` | 35038 | `c1ade1b5aba0b87f29c9d6f61b0fcde5e4bbec5df3ec5afd46070c392833a511` |
| P02 | `bridge/cutter/rea_bridge.py` | 58272 | `35cbd357b00ef74b4f654f515384c0ce8e2d96f4e73f5af0f7a8ce5570e09d0a` |
| P03 | `bridge/hopper_bridge.py` | 58704 | `34da4593e4669d9c3c74ce089deb2e26a42e909cd29c1b5153542462ac49ecf9` |
| P04 | `bridge/mitmproxy/capture.py` | 18996 | `daca512f3f86ab9fdcc3b611954d635bc1ac502d2f681ca60cdc8d87290d3311` |
| P05 | `bridge/pwntools/decoder_runtime.py` | 3157 | `46a066d55314f0a3fa72b2ac14ddcd18bca2c21f975115347cefd2286741e410` |
| P06 | `bridge/pwntools/layout_impl.py` | 24384 | `b57a9e2d1425f70586ec87f3e87ba7d98eeabec919b96675d4f6f57f9be08e22` |
| P07 | `bridge/pwntools/recorded_crash_impl.py` | 11609 | `8dd89f64d7fa1a218b7def48c02a1e3bddfe8d2a47a2816e2e06441b9d394bb8` |
| P08 | `bridge/pwntools/layout.py` | 1383 | `0b3c9a2b511531b3c7d21bc0b09ea8e2eb2767d61313a377f8855bb133c2fb48` |
| P09 | `bridge/pwntools/recorded_crash.py` | 1401 | `1ff9358501ffd02af6e33d1ec759d2018171c33c749049bf3599335eca7a41bb` |
| P10 | `bridge/pwndbg/core_context.py` | 6096 | `04d1bcde3cb8a0d4b33a606a65e847cc7d73751267a5f53f2b2de13e4360038a` |
| P11 | `scripts/hopper-demo-x11.py` | 28086 | `deda5eac6a81867829940db1b653897ee93394d356225e7fd7f30ef02bc81879` |
| P12 | `bridge/pwndbg/launch_impl.py` | 1625 | `a46c8453c154ebf02f666156a41f1d7c7bab7af60ae23eb5661840217785f807` |
| P13 | `bridge/pwndbg/launch.py` | 1389 | `ee2e32337546034af71f0206d88676291b60cbcefe9e7558fdecd5e5b4c23103` |

## Shipped Python files: entrypoints and Rust coverage

### P01: `bridge/native/rea_lldb_tracer.py` — Missing

**Entry:** `__lldb_init_module → rea_trace command → run → trace`.

Runs inside LLDB embedded Python. Launches one owned process, observes selected native/Objective-C call entries from registers and memory, journals bounded events and output, proves target/module identity, then stops its owned process.

**Original integration:** `dist/native/LldbCallTracer.js` — LldbCallTracer.#run; lldb --batch --no-lldbinit; command script import <bridge>; rea_trace <config>.

**Rust entry:** None for this helper.

**Remaining gap:** No Rust observe_native_calls/LLDB bridge. The separate GDB breakpoint fixture and generic process control do not implement LLDB events, identities, budgets, cancellation, or readback.

### P02: `bridge/cutter/rea_bridge.py` — Missing

**Entry:** `create_cutter_plugin → ReaCutterPlugin → _BridgeServer/_RequestDispatcher`.

Cutter Python plugin. Publishes a private descriptor and authenticated loopback protocol, dispatches status/command requests on the application thread, frames bounded replies and reports command completion/unknown outcomes.

**Original integration:** `dist/cutter/CutterBridgeClient.js` — list_cutter_sessions discovery; cutter_command authenticated request.

**Rust entry:** None for this helper.

**Remaining gap:** No Rust Cutter plugin/client or real Cutter lifecycle qualification. An Evidence source enum containing an engine name is not an adapter.

### P03: `bridge/hopper_bridge.py` — Missing

**Entry:** `_run → _serve_connection → _dispatch`.

Authenticated session bridge on Hopper's dedicated Python thread. Reads documents, bytes, addresses, segments, procedures, names, strings, instructions, pseudocode, references and searches; supports navigation, renaming, comments, bookmarks and shutdown.

**Original integration:** `dist/hopper/BridgeLauncher.js` — bridgeBootstrapSource compiles and executes options.bridgeScriptPath; `dist/hopper/HopperProvider.js` — sets bridgeScriptPath to bridge/hopper_bridge.py.

**Rust entry:** None for this helper.

**Remaining gap:** No Rust Hopper session bridge or complete operation mapping. Fixed Ghidra/JADX profiles are different engines and do not replace these Hopper operations.

### P04: `bridge/mitmproxy/capture.py` — Missing

**Entry:** `addons = [OfflineCapture()] → load/running → decode → project_record`.

Offline native mitmproxy tnetstring decoder under caller-supplied mitmdump 12.2.3. Retains and projects records with bounds, validation and redaction. Starts no proxy listener or target requests.

**Original integration:** `dist/browser/history/MitmproxyCaptureAdapter.js` — inspect_web_network_capture; REA_MITMDUMP_COMMAND --no-server -q --set confdir=<owned> --set rea_request_path=<request> -s <bridge>.

**Rust entry:** None for this helper. Related foundations: `src/mcp/rea_browser.rs::run_cli`; `src/mcp/rea_browser_capture.rs::run`.

**Remaining gap:** Rust owned Chrome/CDP capture produces its own bounded fixture observations/HAR. It does not decode native tnetstring files or implement this original inspect_web_network_capture adapter.

### P05: `bridge/pwntools/decoder_runtime.py` — Missing

**Entry:** `lower_resource_limits`; `main(request_path, inspect, failure_type, profile)`.

Shared request/reply boundary for layout, recorded-core and debugger-launch profiles. Lowers inherited address-space/CPU/file-size limits, establishes private cache, reports typed resource/decoder failures and caps complete JSON replies at 64 MiB.

**Original integration:** `bridge/pwntools/layout_impl.py` — loads fixed sibling; runtime['main']; `bridge/pwntools/recorded_crash_impl.py` — loads fixed sibling; runtime['main']; `bridge/pwndbg/launch_impl.py` — loads ../pwntools/decoder_runtime.py.

**Rust entry:** None for this helper. Related foundations: `src/mcp/rea_static.rs::serve_once`; `src/mcp/rea_provider.rs::start/read/cancel`.

**Remaining gap:** General Rust worker budgets and durable ownership are not a compatible port of this decoder reply/resource-failure protocol; no corresponding three decoder profiles are wired.

### P06: `bridge/pwntools/layout_impl.py` — Partial

**Entry:** `inspect_elf(snapshot, cache)`.

Offline ELF EXEC/DYN/REL layout via pinned pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2. Preserves section/segment/symbol/relocation source ranges, RELR encoded data, dependency/interpreter names, derived GOT/PLT and qualified mitigation indicators.

**Original integration:** `bridge/pwntools/layout.py` — fixed sibling exec; `dist/native/pwntools/PwntoolsLayoutProvider.js` — inspect_binary_layout profile via PwntoolsDecoder.

**Rust entry:** `src/mcp/rea.rs::inspect_artifact → inspect_bytes → parse_elf`; `src/mcp/rea_binary.rs::inspect_elf_bytes`; `src/mcp/rea_binary_parser.rs::parse`

**Remaining gap:** Only bounded ELF headers, sections, program headers and declared symbols overlap. Native preview uses hepta.rea.elf-structure.v1 and partial coverage; it omits relocation/RELR, symbol versions, dependencies, GOT/PLT and mitigation semantics, and does not expose the original inspect_binary_layout Evidence contract. No full helper differential is claimed.

### P07: `bridge/pwntools/recorded_crash_impl.py` — Missing

**Entry:** `inspect_core(snapshot, cache)`.

Offline Linux little-endian x86_64/aarch64 ELF core decoding. Preserves segment/note ranges and bytes, interprets exact CORE NT_PRSTATUS register/thread data and selected NT_SIGINFO fields, and keeps current live identity and unavailable semantics unknown.

**Original integration:** `bridge/pwntools/recorded_crash.py` — fixed sibling exec; `dist/native/pwntools/PwntoolsRecordedCrashProvider.js` — inspect_recorded_crash profile via PwntoolsDecoder.

**Rust entry:** None for this helper. Related foundations: `src/mcp/rea_elf_notes.rs::inspect`; `src/mcp/rea_elf_notes_parser.rs::parse_elf_notes`.

**Remaining gap:** Rust ELF notes inspect raw note structures/GNU note meanings under a different public operation. There is no recorded-core architecture/ABI/register/signal adapter, pairing contract, or original inspect_recorded_crash output.

### P08: `bridge/pwntools/layout.py` — Missing

**Entry:** `module top level → compile/exec fixed layout_impl.py`; `resource_exit`.

Outer typed-resource guard for ELF layout, including sibling import/compile failures. Writes owned resource.failure M/F marker and exits 75/76 for directly observed MemoryError/ENOMEM/EFBIG.

**Original integration:** `dist/native/pwntools/PwntoolsDecoder.js` — #inspect executes REA_PWNTOOLS_PYTHON -I <profile.bridge> <resource.failure> <request.json>; `dist/native/pwntools/PwntoolsLayoutProvider.js` — selects layout.py.

**Rust entry:** None for this helper.

**Remaining gap:** The native ELF preview is a separate bounded API and does not implement this entrypoint, failure marker classification, decoder ownership or original layout output boundary.

### P09: `bridge/pwntools/recorded_crash.py` — Missing

**Entry:** `module top level → compile/exec fixed recorded_crash_impl.py`; `resource_exit`.

Outer typed-resource guard for recorded-core decoding; covers fixed sibling loading and observed allocation/file-limit failures with owned failure marker.

**Original integration:** `dist/native/pwntools/PwntoolsDecoder.js` — #inspect; selected fixed profile bridge; `dist/native/pwntools/PwntoolsRecordedCrashProvider.js` — selects recorded_crash.py.

**Rust entry:** None for this helper.

**Remaining gap:** No corresponding recorded-core Rust worker, typed failure protocol or public readback adapter.

### P10: `bridge/pwndbg/core_context.py` — Missing

**Entry:** `main → inspect`.

Fixed GDB embedded-Python, core-only pwndbg context. Loads caller-supplied pwndbg initialization, requires 2026.09.15, disables automatic target/library discovery, establishes a core-only inferior and reports mapping candidates with current file identities unknown.

**Original integration:** `bridge/pwndbg/launch_impl.py` — generates fixed GDB -ex Python compile/exec command for this sibling; `dist/native/pwndbg/PwndbgCoreContext.js` — inspectPwndbgCore include_debugger_context stage.

**Rust entry:** None for this helper.

**Remaining gap:** No Rust pwndbg core-only context or mapping projection. A real GDB breakpoint/cancel exercise does not cover this helper or its version, core-boundary and no-host-file rules.

### P11: `scripts/hopper-demo-x11.py` — Missing

**Entry:** `main → run_probe/run_launch`.

Hopper Linux private-X11 helper. Probes direct or user/mount-namespace display strategy, owns Xvfb/Hopper children, authenticates the demo dialog and activates it through Xlib/XTest, and tears down its owned resources.

**Original integration:** `dist/hopper/LinuxPrivateDisplayProbe.js` — privateDisplayProbeCommand: /usr/bin/python3 <helper> --probe --strategy ...; `dist/hopper/BridgeLauncher.js` — linuxDemoCommand: direct Python or /usr/bin/unshare wrapper launching Python helper.

**Rust entry:** None for this helper.

**Remaining gap:** No Rust X11 display probe, Hopper demo dialog boundary or matching process/display cleanup. No commercial engine was installed for this audit.

### P12: `bridge/pwndbg/launch_impl.py` — Missing

**Entry:** `launch(snapshot, cache) → os.execve(GDB)`.

Lowers inherited limits through decoder_runtime, reads the owned request and replaces the original process with fixed no-init batch GDB. Generates only a fixed sibling core_context.py Python exec expression; caller paths remain request data.

**Original integration:** `bridge/pwndbg/launch.py` — fixed sibling exec.

**Rust entry:** None for this helper.

**Remaining gap:** No Rust fixed core-only debugger launcher wired to the original provider. Generic executable launch is not this protocol; selected GDB/pwndbg identities and recovery remain unqualified.

### P13: `bridge/pwndbg/launch.py` — Missing

**Entry:** `module top level → compile/exec fixed launch_impl.py`; `resource_exit`.

Typed-resource guard for the owned debugger launcher, preserving the same observed allocation/file-limit marker semantics across sibling loading.

**Original integration:** `dist/native/pwndbg/PwndbgCoreContext.js` — inspectPwndbgCore executes REA_PWNTOOLS_PYTHON -I <launch.py> <resource.failure> <request.json>.

**Rust entry:** None for this helper.

**Remaining gap:** No direct Rust replacement for this launcher guard or its original provider contract.

## Generated and inline Python

These are separate logical entries. The generated GDB Python command in P12 is a fixed loader for P10 and is recorded under those two shipped files; it is not counted as an additional implementation.

| ID | Produced or executed path | Generator or entry | State |
| --- | --- | --- | --- |
| G01 | `<owned Hopper session>/bootstrap.py` | `bridgeBootstrapSource(session, options, ownsProcessLifetime, loadedPath)` | Missing |
| G02 | `/usr/bin/python3 -I -S -B -c <query>` | `inspectLinuxHopperPythonRuntime → runtimeCommand` | Missing |
| G03 | `artifacts/check_<bundle-name>/verify.py` | `bundleVerifier(plan) emits async verify(mcp_url) and answered_status` | Missing |

### G01: generated-python

Injects original session binding and optional request limit, then compiles/executes the fixed Hopper bridge on Hopper's Python thread.

**Called by:** `dist/hopper/BridgeLauncher.js::#writeBootstrap; launch arguments -Y <bootstrap>`.

**Generator source:** `dist/hopper/BridgeLauncher.js`, SHA-256 `cf81995b73d93941fcf95c2df21922776bd4b0ba7288fc9d5fb11efa2fec563d`.

**Exact generator definition SHA-256:** `36bd94065a527ea612b1fc55c05b145bcadf31496bf2d87148a3bbd046e7af6a` (1123 UTF-8 bytes).

**Materialized SHA-256:** configuration-dependent. Output is parameterized and contains a per-session token. The exact generator source slice is hashed; no synthetic fixed output is represented as the universal helper identity.

**Parameters:** `session.socketPath`, `session.token`, `session.runId`, `loadedPath`, `ownsProcessLifetime`, `options.bridgeMaxRequestBytes`, `options.bridgeScriptPath`.

**Rust status:** Missing. No Rust Hopper bootstrap/session adapter.

### G02: inline-python

Inspects distribution Python version and configured shared-library path, probes ctypes.CDLL, and distinguishes loadable, unavailable and unknown from failed query.

**Called by:** `dist/application/LinuxHopper.js setup/verification and dist/doctorRuntime.js`.

**Generator source:** `dist/application/LinuxHopperPython.js`, SHA-256 `8646d4e68498005086b53c5a0ad82498ae4c30d4e8179092781c12b0e7f836c3`.

**Exact executed Python SHA-256:** `f7c8800fa57b2bd3f135dc7fc77eb0b40565f0783110b4157bbc19e2b9578c6e` (673 UTF-8 bytes).

**Rust status:** Missing. No Rust equivalent Linux Hopper shared-Python-runtime probe/typed result.

### G03: generated-python

Original public environment-export artifact. Uses Python MCP streamable-HTTP client to list tools and optionally call one retained GET tool, then checks count and status. It is not a qualification script introduced by this project.

**Called by:** `dist/application/environment/environmentBundle.js::planEnvironmentBundle; exported tasks/smoke.json env_outcome_verifier`.

**Generator source:** `dist/application/environment/environmentBundle.js`, SHA-256 `18430e689750fbcc7aa9d01a8feca5078e87898942cd3d613201fc71f8589e49`.

**Exact generator definition SHA-256:** `0feb8991cf387e212692f42c24f8330c3094ebc3aec46cc2eb57596018ecf3f5` (2090 UTF-8 bytes).

**Materialized SHA-256:** configuration-dependent. Output depends on the captured environment plan. Exact generator source slice is hashed; there is no one materialized SHA for every exported bundle.

**Parameters:** `plan.state.served`, `plan.toolCount`, `plan.check.tool`, `plan.check.status`.

**Rust status:** Missing. No Rust environment bundle verifier/export implementation found; schema family names or Evidence environment metadata do not implement it.

G01 and G03 hashes cover the UTF-8 source beginning at the recorded `export const` declaration and ending at its final semicolon, before the following newline/comment/declaration. G02's 673-byte query contains no interpolation or escape transformation, so its exact executed bytes have a single stable hash. No session token was materialized for this inventory.

G03 belongs to the reference's public environment export feature. Its filename `verify.py` does not make it one of this project's test scripts: the original product emits it into an exported bundle and the exported smoke task invokes it.

## External Python dependencies and unresolved identities

| Dependency | Original selection or execution | Identity boundary |
| --- | --- | --- |
| pwntools interpreter/packages | `REA_PWNTOOLS_PYTHON`; pwntools 4.15.0, pyelftools 0.33, Unicorn 2.1.2 | The frozen package carries its adapters, not the selected interpreter or these package contents. Version checks do not establish content SHA-256. |
| pwndbg initialization | `REA_PWNDBG_GDBINIT`, `REA_PWNDBG_VENV_PATH`, `REA_PWNDBG_GDB`; required pwndbg 2026.09.15 or its build suffix | P10 explicitly compiles/executes the selected external Python init. No concrete init/venv was selected, executed or hashed by this source inventory. |
| mitmdump/mitmproxy | `REA_MITMDUMP_COMMAND`, expected 12.2.3 | The adapter is pinned above; the separately selected application needs an execution identity. |
| Embedded engine Python APIs | LLDB `lldb`, Cutter `cutter`, Hopper's Python API/thread | These APIs belong to installed engines. Their source and binary identities are outside the packed helper bytes. |
| Agentenv readiness probe | Original bundle Dockerfile installs `python3` for the external framework's container-readiness probe | The package contains the Dockerfile recipe and G03, but not the framework's readiness Python body. Its unseen bytes are not invented or marked covered. |

These configuration-dependent dependencies remain explicitly unpinned here. They do not receive fake fixed hashes or additional “covered helper” counts.

## Related Rust work and what it establishes

The concrete partial overlap is `rea::inspect_artifact → inspect_bytes → parse_elf → rea_binary::inspect_elf_bytes`. The native parser reads bounded ELF sections, program headers and declared symbols from captured bytes. Its report is `hepta.rea.elf-structure.v1`; rows and complete report size are bounded, and its own coverage remains partial. It explicitly does not decode relocations, symbol versions, dependencies or runtime/loadability conclusions. Original P06 additionally preserves relocation/RELR provenance, linkage names, derived GOT/PLT and mitigation indicators under a different contract.

The separately wired `inspect_elf_notes` route has its own original contract and GNU note handling. It does not implement P07's Linux recorded-core ABI, per-thread registers, signal interpretation or the optional P10 pwndbg mapping stage.

The native browser worker uses owned Chrome/CDP for bounded local-resource capture. That work does not replace P04's offline native mitmproxy decoder. A prior comparison against this project's `dc_compat/chromium_capture.py` helper is outside the frozen package inventory and cannot close P04.

The fixed provider enum contains GNU readelf, GNU objdump, JADX and Ghidra. Its owner-bound scratch work improves those fixed engines' operation, cancellation and recovery. It does not create Hopper/Cutter/LLDB/pwndbg adapters. Original-process-group stop proof is also narrower than proof that every possible escaped descendant has stopped.

The general operator supervisor in `src/mcp/runtime/jobs.rs` still contains Python. The engine cleanup changes reused that existing durable owner; they did not Rust-port the whole supervisor. Existing `src/mcp/runtime/document_formats.py` and `src/mcp/runtime/binary_file.py` are additional Hepta helpers outside this fixed REA inventory. Native REA routes do not make the whole deployed runtime Python-free.

## Enumeration and exclusions

The inspection enumerated every physical `*.py` under the fixed package and parsed its AST without executing the helper. Canonical caller modules and emitted-code recipes were then inspected. Bundled `dist/mcp` and `dist/cli-runtime` copies retain their own file hashes in the JSON, but references to the same physical Python helper are counted once.

The following are excluded from the helper counts:

- This project's qualification, test, observer and fixture scripts.
- JavaScript implementations of Python bytecode, Marshal and PyInstaller inspection, which read Python artifacts without invoking CPython.
- Python mentions in GDB command-rejection prefix checks.
- Ghidra/JADX Java bridges and Electron JavaScript hooks, which remain separate implementation and engine-qualification scope.
- Duplicate bundled JavaScript call sites.
- Unseen external interpreter/module/framework bytes, whose dependency boundaries are listed explicitly above.

Source inspection jobs are recorded in the JSON. It records the clean Rust snapshot and exact source hashes; it contains no fabricated runtime-pass results.

## Closure required for this ledger

Each missing or partial row still requires a corresponding production Rust entry or a documented, tested equivalent integration. Closure must cover successful results, malformed and unsupported inputs, typed unknown states, bounded complete output, original ownership, cancellation, cleanup and post-cancellation/restart readback against the fixed reference behavior. External engines and Python packages need exact installed identities for any comparison that uses them.

The final same-binary Ghidra/JADX/Chrome qualification is tracked separately. It may close concrete tested engine scenarios, but it cannot change these helper statuses without their own implementation and evidence.
