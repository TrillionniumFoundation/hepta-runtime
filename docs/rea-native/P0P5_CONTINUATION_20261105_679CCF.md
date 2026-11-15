# REA P0–P5 continuation: syntax, preload wrappers and browser observation

This continuation starts from local source commit
`c759624715f24d5c7f09d66df34a77043a6950b2`. It is an isolated worktree;
the separate in-progress recorded-core merge is not included.

The overall REA replacement and production decision remains **HOLD / NO_GO**.
The changes below are bounded corrections, not qualification of all 229
published operations.

## Fixed original identities

- Published package: `rea-agents@6.8.0`, archive SHA256
  `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`.
- Separately pinned Git source:
  `morluto/rea@93b8b82db70279e40f484114cff9dc1958dc14ee`.
  Source declarations and the published npm operation catalog are distinct.
- Node: `v22.23.4`, executable SHA256
  `94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90`.
- Original public JSON/Evidence corpus: 116 inputs, SHA256
  `289d512884e2ee47fa784ad6f70d76813da1e2f54b84a9b35522320b63f0b4fb`.
  The unchanged collector is now retained as
  `scripts/rea_json_differential.py`; its SHA256 is
  `a50826baf7d3fa6cc0634befff43fbb9faadff8574c2e99506068905fd2c6f99`.

## JSON diagnostics and input custody

The bounded observer records the first grammar error and follows the pinned
Node/V8 diagnostic's UTF-16 positions, line/column accounting and short context.
It keeps a fixed depth stack and 50 UTF-16 code units of context, rather than
retaining a copy of the input. The value parser still owns acceptance.

For the existing small-file profile (at most 8 MiB), an independent value-parser
rejection is drained through the same checked reader. Actual EOF, UTF-8,
I/O, cancellation and native resource limits are still enforced. A complete
rejected read now also participates in the two-read length/digest check, so a
diagnostic is not returned from bytes that changed between admission and parsing.

Independent review found an additional parser-classification boundary:
an incomplete Unicode escape can already contain an invalid character while
serde reports EOF before validating its four digits. A captured first grammar
error must take precedence for either syntax or EOF rejection.

Valid lone-surrogate values and nonfinite numeric results are still explicit
value-representation gaps. If the original diagnostic itself contains an
unpaired UTF-16 code unit, the implementation keeps an explicit gap instead of
replacing it with U+FFFD.

Small malformed inputs can require reading more of the suffix than the previous
native implementation. This is an explicit cost, not a performance improvement.
The large-file streaming profile is unchanged.

## JavaScript and TypeScript preload declarations

A top-level BrowserWindow options object was skipped when wrapped in parentheses
or a transparent TypeScript expression. The parser now uses Oxc's existing
`get_inner_expression` before inspecting that object. Dynamic values, spreads
and shadowed constructors remain unknown or excluded.

The graph profile advances to
`hepta.javascript-selected-source-graph.v4`. Old v1/v2/v3 continuation
identities are rejected even when source bytes have not changed. Tests retain
the historical identities as negative controls.

The finite harness uses seven authored inert fixtures. Node's TypeScript
transformation and a stub constructor provide one independent observation.
A second frozen oracle comes from the actual npm public
`analyze_javascript_application` operation on the original source bytes: all
seven report the literal preload, while the c759 native baseline missed six.
The harness binds each fixture's source SHA and compares the same presence and
literal projection against both oracles. This does not execute user source or
qualify the complete upstream application graph, Envelope, Evidence or Electron
runtime behavior. Raw MCP responses and receipt identities are retained in the
external evidence, with the portable original projection committed as a fixture.

## Chrome environment observation

The former environment assertion read the initial `/proc/<pid>/environ`
memory region. In the actual failing Chrome process, almost all bytes were NUL
and the remaining bytes matched the rewritten process-title tail. Reading that
region cannot by itself establish the current `getenv()` result.

Normal capture and cancellation jobs remain uninstrumented. An additional,
separate test uses a pinned C constructor observer via the existing job
environment mechanism. It records the actual Chrome ELF's four private
environment values before main, binds PID/PGID/start ticks and executable
identity, and is followed by the normal owned cancellation and cleanup checks.
Eight real Chrome exec negative controls omit or move each required directory
outside the selected profile and must be rejected.

The observer does not modify environment values. There is no new runtime hook
or environment-admission exception. Its receipt qualifies only that instrumented
exec boundary. It does not certify another uninstrumented process's getenv, nor
the instrumented process's environment after the constructor. Original RED
receipts are retained, not reclassified.

## Verification and remaining work

The final result record must bind the implementation commit, selected source
inventory, Cargo.lock, Rust 1.95.0, actual runtime SHA256, provider configuration,
commands, raw logs and authoritative job terminals.

Required checks for this continuation are the existing two-feature matrix,
the four separately selected original Evidence/number/schema tests, the
unchanged 116-input public MCP differential, the JavaScript fixture comparison,
and actual Ghidra/JADX/Chrome runs on the same runtime artifact.

A green finite corpus does not establish full schema or protocol equivalence.
The session Evidence registry still requires authenticated persistence and
cold-restart permission/recovery qualification. Complete format coverage,
licensed-provider availability, native device/dynamic adapters, cross-host
interruption recovery, full cost comparison, upgrade/rollback and deployment
qualification remain open.
