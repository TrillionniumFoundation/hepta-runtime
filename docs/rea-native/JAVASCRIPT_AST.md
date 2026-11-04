# Native JavaScript, TypeScript and Electron AST graph

`rea_inspect_javascript_graph` extends the existing package declaration inspector
with a real Oxc parser and lexical symbol analysis in the shipped Rust runtime.
It returns observations over an explicitly selected set of source files. It does
not load a project or execute JavaScript. Node and Electron are not production
dependencies for this tool.

## Tool sequence and source identity

Use `rea_inspect_javascript_package` to inspect a selected `package.json` first.
Its `main`, `exports`, dependency and script values remain declarations. Choose
the source files to inspect, their logical IDs and their grammars explicitly:

```json
{
  "sources": [
    { "id": "src/main.ts", "path": "/allowed/project/src/main.ts", "syntax": "typescript", "module_kind": "module" },
    { "id": "src/preload.cjs", "path": "/allowed/project/src/preload.cjs", "syntax": "javascript", "module_kind": "commonjs" },
    { "id": "src/renderer.tsx", "path": "/allowed/project/src/renderer.tsx", "syntax": "tsx", "module_kind": "module" }
  ],
  "collection": "electron_calls",
  "limit": 64
}
```

Absolute physical paths must pass the runtime's configured controller workspace
root admission. The parser receives copied UTF-8 source bytes and normalized
relative logical IDs, without original physical paths or controller credentials.
Logical IDs are caller-selected names for matching relative module specifiers;
they are not filesystem authorization.

Collections are `summary`, `imports`, `exports`, `electron_calls`, `ipc_edges`,
and `unknowns`. The summary returns counts and source identities. Each source
identity includes its full byte hash, byte length and explicit grammar. The
graph hash binds the complete selected source set and parser profile. Supply
that hash in `expected_graph_sha256` for every page with `offset > 0`; changing
any selected source or grammar invalidates continuation. Optional per-source
`expected_sha256` values also reject stale bytes at admission. Reordering the
selected sources does not change their graph identity.

The graph hash identifies the complete copied source set and its parser profile;
it is not a checksum of all graph result rows. Changes to analysis or collection
ordering semantics must advance the versioned
`hepta.javascript-selected-source-graph.v1` profile. Independent reads of several
files do not constitute an atomic filesystem snapshot. Results use the native
`hepta.rea-javascript-graph.v1` record format and explicitly set
`rea_evidence_compatible: false`.

## What the AST inspection establishes

- Oxc parses JavaScript, TypeScript, JSX or TSX according to the supplied grammar
  and module mode. Semantic syntax checks and regular-expression parsing are
  enabled. Parser diagnostics, semantic syntax diagnostics and unsupported
  lone-surrogate strings refuse the inspection; recovered invalid ASTs are not
  returned as valid graphs.
- Imports include ESM imports and reexports, literal or dynamic `import()` and
  unshadowed CommonJS `require()`. ESM bindings retain imported names, local
  aliases, per-binding type-only flags and source byte spans. Exports retain
  ESM names and reexport sources, plus syntactic CommonJS assignment observations.
  An export's `local_name` is a syntactic name hint; it does not establish
  runtime live-binding or default-expression evaluation behavior.
- Relative imports may link to exact matching selected logical IDs. If no exact
  ID matches, the report lists matching selected extension/index candidates. The tool
  does not run Node, TypeScript or bundler resolution, open dependencies, follow
  package exports conditions, or choose an arbitrary candidate.
- Electron imports and unshadowed `require("electron")` establish lexical
  origins. Direct aliases and destructuring are followed; shadowed identifiers,
  lookalike package names and reassigned variable bindings are excluded from
  receiver inference.
- Detected Electron callsites cover `ipcMain` handler declarations,
  `ipcRenderer` send/invoke/listener calls, `webContents` send calls,
  `contextBridge` exposure keys and direct `BrowserWindow` preload declarations.
  Calls and exports retain UTF-8 byte spans, including sources with astral and
  non-ASCII characters.
- A shared literal channel and compatible API roles produce an IPC candidate
  edge. Every edge sets `runtime_observed: false` and `process_pair_proven: false`.
  Dynamic module specifiers, channel/key expressions, member names, CommonJS
  export names and detected dynamic preload declarations appear in `unknowns`.

## Remaining scope

This is a bounded selected-source analysis, with
`complete_application_graph: false`. It does not establish branch reachability,
window ownership, live listeners, renderer/main process pairing, sender
validation, payload compatibility, successful IPC delivery, or actual bridge
exposure. Property mutation, `eval`, factories, indirect calls and general
interprocedural dataflow are not resolved. The list of reported unknowns covers
detected syntax patterns; it is not a claim that every unmodeled behavior has
been enumerated.

Package scripts, imported modules, preload expressions, URLs, source maps and
native addons are never loaded implicitly or executed. Explicit `source.asar`
selection can now admit a packed regular ASAR member through the bounded
[ASAR reader](ASAR.md), without extracting it to the filesystem. The member's
complete admitted source bytes feed the same Oxc graph pipeline. Plain-file
requests retain their original canonical identity; ASAR acquisition adds separate
archive provenance without changing the logical source/content graph identity.
Links and unpacked sidecar files remain declarations and are not followed.

The separate [source-map declaration reader](SOURCE_MAP.md) decodes explicitly
selected local maps and point queries; it does not automatically associate a map
with an AST graph or authenticate the claimed generated/original relationship.
Minifier/deobfuscation semantics, arbitrary application resolution, implicit
archive traversal and live Electron instrumentation require further capability
and qualification work. This tool does not claim full REA 6.8.0 behavioral parity.

## Resource and process boundaries

The admission limits are 16 selected sources, 1 MiB per plain file or selected
ASAR member, and 4 MiB total UTF-8 source. ASAR header/member verification has
its own bounded acquisition worker before the Oxc parser.
The parser rejects more than 200,000 AST nodes in one source and more than
10,000 combined observations or IPC candidate edges. Pages contain at most
256 rows and one response is at most 1 MiB; oversized pages fail explicitly.
Two inspections may run concurrently in one controller.

Production parsing uses the shipped `hepta-runtime rea-javascript-worker`
subcommand over bounded stdin/stdout pipes. The worker clears its environment,
starts at `/`, has one absolute 20-second worker-phase controller deadline, and on Unix sets 12 CPU
seconds, 768 MiB address space and 64 descriptors. Linux additionally uses
parent-death protection and the existing REA post-input seccomp restrictions.
Timeout and output errors kill and reap the worker. The MCP handler also passes
its request cancellation token explicitly. It checks cancellation before admission
and spawning, and the running worker responds to the token by killing and awaiting
the same owned child before releasing the parser slot. An already-started bounded
file read retains the slot until that read completes; cancellation does not detach
the read and admit an unbounded background queue.

This cancellation path requires the handler to remain running and observe the
request token. Arbitrary future destruction or runtime exit still uses the existing
`kill_on_drop`/Tokio cleanup mechanism and does not establish synchronous reaping.
Non-Unix qualification is not claimed. This short internal parser worker does not
add an independent supervisor, daemon or durable job store.

## Independent qualification

`tests/fixtures/rea_javascript` contains authored JS, TS, TSX and CommonJS
fixtures, a package declaration, real Electron API syntax, false-positive
controls, dynamic expressions, exports and Unicode offsets. Its CommonJS
fixture includes a write marker which must remain absent during inspection.

`scripts/rea-javascript-ast-reference.mjs` uses separately installed, exact
`@babel/parser@8.0.6` and `@babel/traverse@8.0.6` as an independent AST and scope
oracle. It parses fixture text without importing it, calls the actual shipped
Rust worker, compares imports/bindings, export names, Electron callsites and
candidate edges, and saves expected and actual values even on a mismatch.
The report records parser versions, the binary hash, every fixture hash and the
selected graph hash. Object key order and collection row order are normalized
for comparison; nested binding order and duplicate observations remain significant.

```text
npm install --prefix /path/to/oracle --ignore-scripts --no-audit --no-fund --save-exact @babel/parser@8.0.6 @babel/traverse@8.0.6
node scripts/rea-javascript-ast-reference.mjs tests/fixtures/rea_javascript /path/to/oracle /path/to/hepta-runtime /path/to/reference.json
cargo test --locked --lib rea_javascript_graph -- --test-threads=1
cargo test --locked --test rea_javascript_graph_external -- --test-threads=1
```

The external test exercises the shipped stdio MCP registration, package-to-source
workflow, worker, independent Babel import observations, restart determinism,
bound continuation, path/symlink refusal, malformed/oversized input and recovery
after failure. Qualification results and build/source identities are recorded
separately under `docs/qualification/rea-javascript-ast-20261104-r1`.
