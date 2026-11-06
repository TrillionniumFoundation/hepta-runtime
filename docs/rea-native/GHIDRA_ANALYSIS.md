# Bounded Ghidra function analysis

This extends the Rust static-provider contract and worker, using the existing durable job owner, with real Ghidra function discovery, selected-function inspection, cross-references and native decompilation. It requires an explicitly configured, revision-bound Ghidra installation and Java 25. Legacy and revision 2 profiles use Ghidra 12.2; revisions 3 and 4 separately admit the fixed 12.1.4 distribution used for the original REA comparison. Ghidra's Java/native engine remains an external dependency; this is not a Rust rewrite of the decompiler. In the previously qualified 12.2 operator deployment, the existing Python 3 launcher and durable runner start the Rust `rea-static-worker`, which invokes the fixed Java bridge and installed Ghidra native engine. That historical qualification does not transfer to revisions 3/4 or to a newly built runtime.

The existing MCP surfaces remain `rea_static_profiles`, `rea_static_start`, `rea_static_status`, `rea_static_read` and `rea_static_cancel`. There is no second task registry, background service or recovery handle. The complete original request identifies the existing durable job after replay, cancellation or a controller restart.

## Versioned profile and compatibility

`GhidraEngineProfile.bridge_revision` is optional in serialized profiles:

| Value | Engine | Bridge | Admitted operations |
| --- | --- | --- | --- |
| Absent | 12.2 | Original `rea_ghidra_bridge.java`, unchanged bytes | `inventory` only |
| `2` | 12.2 | Repaired `rea_ghidra_inventory_v2.java` or `rea_ghidra_analysis_bridge.java` | Explicitly allowed `inventory`, `functions`, `function`, `xrefs`, `decompile` |
| `3` | 12.1.4 | Separate `rea_ghidra_inventory_1214_v3.java` or `rea_ghidra_analysis_1214_v3.java` | The same explicit operation selection, with independently bound engine and bridge identities |
| `4` | 12.1.4 | Separate `rea_ghidra_inventory_1214_v4.java` or `rea_ghidra_analysis_1214_v4.java` | The same operation names; analysis requires the fixed x86:LE:64:default/gcc defaults, selected addresses resolve by complete body ranges, and functions include a separate external inventory |
| Any other explicit value | Refused | None | None |

Absent new fields remain absent when serialized. Existing request/profile identities are therefore preserved. Revision 2 changes the profile hash and selects a different bridge hash. The returned report includes the admitted engine profile and exact embedded bridge SHA-256; a new bridge is never interpreted as the old bridge.

Revisions 3 and 4 require engine version `12.1.4` and release ZIP SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`. Legacy and revision 2 still require version `12.2` and SHA-256 `2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67`. Cross-version or cross-revision results are rejected even when a caller recomputes their report digest. Installation manifests, source bytes, Java runtime files and cleanup observations retain their existing validation requirements. Adding a profile does not establish original REA result or lifecycle equivalence.

The original byte-array importer has a real Ghidra 12.2 failure on a dynamically linked ELF: the anonymous byte provider has a null name, and Ghidra's library-name comparator dereferences it even when target-library loading is disabled. Revision 2 passes a fixed named `ByteArrayProvider("hepta-owned-input", bytes)`. No user path or library name is substituted. It retains disabled target-library loading and project linking.

The legacy bridge remains solely to preserve its explicit historical identity and existing receipts. New profiles must explicitly choose the revision matching their fixed installation. Updating a profile does not authorize replaying an uncertain old request as a different job; retain the original profile, request and key for observation of the original job.

## Fixed operations

| Operation | Selection | Result and limits |
| --- | --- | --- |
| `inventory` | Captured ELF | Memory/imported-symbol inventory without automatic analysis or decompilation. Revision 2 also binds observation source SHA-256 and size. |
| `functions` | Captured ELF | Fixed analysis; at most 4,096 internal functions scanned and 128 rows returned, with scan completeness and omitted counts. |
| `function` | Exact entry in revisions 2/3; entry or containing-body address in revision 4 | Entry, qualified name/prototype, body bounds/size and thunk metadata after fixed analysis. |
| `xrefs` | Exact entry in revisions 2/3; entry or containing-body address in revision 4 | Incoming references to that entry; outgoing references from the selected function body. Each direction scans at most 4,096 references and returns at most 128 rows, with scope/completeness/omission fields. |
| `decompile` | Exact entry in revisions 2/3; entry or containing-body address in revision 4 | Real `DecompInterface` native decompilation; completion status, bounded C preview, full C length/digest and preview digest/completeness. Native child cleanup must be confirmed. |

The optional request field `function_address` is required for `function`, `xrefs` and `decompile`, and refused elsewhere. It is canonical lowercase hexadecimal such as `0x401106`: no uppercase, leading zeroes, symbol name, range, space prefix, expression or script. Revisions 2 and 3 retain their exact internal-entry requirement and their original bridge bytes. If those revisions do not find an exact internal entry, the real backend fails and no successful mapped facts are returned.

## Revision 4 address and inventory semantics

Revision 4 returns `hepta.rea.ghidra-analysis.v2` under analysis profile
`hepta.ghidra.12.1.4.elf-x86_64-default-functions.v1`. It first resolves an exact internal
entry and otherwise asks Ghidra for the function containing the requested
memory address. The original `function_address_requested` remains unchanged;
the resolved entry is in `function.entry_address`, and `function_resolution`
is `entry` or `containing`. Request keys, profile hashes and recovery identities
are never rewritten to the resolved entry.

Each selected function reports all of its address ranges, up to 128 ranges.
The Rust consumer checks canonical endpoints, address order, non-overlap,
count, extrema and total address count, and requires both the entry and
requested address to be inside one of those ranges. A gap between two body
ranges is not part of the function even if it lies between the minimum and
maximum addresses. Incomplete or oversized range reports fail rather than
being used to establish containment. The ranges remain observations of the
pinned engine; these checks do not independently redisassemble the input.

For `functions`, the existing `functions` array remains the internal inventory.
The separate `external_functions` array retains canonical `EXTERNAL:0x...`
identities, with independent scanned, returned, omitted and completeness
fields. Each inventory scans at most 4,096 entries and retains at most 128
rows before response-budget reduction. Equal numeric offsets in memory and
EXTERNAL space are distinct identities. External entries are not admitted
through the memory-only selected-function request field.

Revision 4 adds body selectors, explicit external inventory and a separately
identified default-analyzer profile. A finite Java diagnostic on the fixed
owned input recovered 13 internal plus 2 external functions and matched the
original npm run's 15 rows by address, name, external/thunk flags, thunk target
and symbol source. Complete Evidence, original error schemas, other original
address forms and paired cancellation remain separate qualification gates.
New summaries use `hepta.rea.static-summary.v2`; historical summary shapes remain unchanged.

## Revision 4 fixed default options

The profile requires language `x86:LE:64:default` and compiler `gcc`. It leaves
Ghidra's fresh defaults unchanged and checks all 146 options before and after
analysis against SHA-256
`a5531d741cf6e4e42215ea1f4268049600b80c3a03ab7d3586bd3a7bbb7acd75`.
The canonical format is `hepta.ghidra.analysis-options.key-type-class-value.v1`:
an array sorted by option name, containing each item's name, Ghidra option
type, Java value class and value in that order. Primitive values retain their
JSON types, enums use their names, and the fixed bridge's compact JSON encoding
defines the bytes. The complete snapshot is retained in the
[default-profile evidence](../qualification/rea-ghidra-v4-default-20261106-r1/README.md).

Exact sorted lists require 26 enabled analyzers and four disabled defaults:
Aggressive Instruction Finder, Condense Filler Bytes, Decompiler Parameter ID,
and Variadic Function Signature Override. The two observed Max Threads values
remain 2; JVM ActiveProcessorCount remains 1. The bridge does not enable all
analyzers or rewrite defaults. Other language/compiler/option identities fail.

The authenticated original npm profile declares ghidra-default, and its launcher
applies no analyzer override for that selection. Its complete historical option
snapshot was not captured directly; comparison to the fresh snapshot remains
an explicit inference. The native profile does not apply the original's
NoReturnFix post-script. The retained original log for this owned fixture
records cleared=0, sites=0 and refit=0; other inputs remain an open difference.

Revision 4 installation manifests cover the complete `Ghidra/` and `GPL/`
subtrees under the existing file, byte, symlink and regular-file checks, before
and after execution. They require the fixed release digests for both
`GPL/DemanglerGnu/Module.manifest` and
`GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_41`.
The external harness compares every admitted member to the pinned release ZIP.
GPL JARs remain excluded from the classpath. The observed installation has
3,139 files, including 137 GPL files; revisions 2/3 retain their original
Ghidra-only scope. This does not attest all host shared libraries or qualify
another host platform.

The earlier unpublished four-analyzer revision-4 candidate used profile
`hepta.ghidra.12.1.4.elf-functions.v2` and bridge SHA-256
`95f26c924c445fce23108ce718667ed72def831fed63a1e36589c7b1177edcc7`.
Its eight Java API checks and 12+1 inventory are retained under that historical
identity. The current default candidate has its own source hashes and receipts;
old 3,002-file checks are not retroactively expanded to include GPL.

The artifact must be owned, inside the profile's input roots, and match the supplied artifact SHA-256. Sealed captured ELF bytes are used for import; the target is not executed. The worker does not accept arbitrary flags, analyzer names, output paths, plugins or scripts.

## Analysis and resource boundaries

The revision 2 analysis profile is `hepta.ghidra.elf-functions.v1`; revision 3 uses `hepta.ghidra.12.1.4.elf-functions.v1`. For these historical revisions, exactly four recognized analyzers are enabled:

- Disassemble Entry Points
- Function Start Search
- Stack
- Subroutine References

Other recognized analyzers are disabled, and their count/name-set digest is reported. Stack analysis is restricted to one thread. This is deliberately a partial analysis profile. It does not claim all Ghidra headless analyzers, debug-symbol loading, language/architecture parity or recovery of every function.

The current bounds are: input at most 8 MiB, analysis monitor 30 seconds, native decompilation monitor 15 seconds, overall configured operation deadline at most 120 seconds, JVM heap 512 MiB and returned stdout at most 64 KiB. Profile admission requires at least 1 GiB memory; the qualification profile uses 1.5 GiB. Installed files are verified against a sealed manifest and their identities rechecked before and after engine use.

Full decompiled C is limited to 1 MiB before previewing. At most 8,192 UTF-16 code units are initially retained, bounded to 32 KiB of UTF-8; fitting the response budget may reduce the preview further. Full/preview digests and `c_code_complete` distinguish those cases. Functions and reference rows can likewise be reduced to fit the response budget, without hiding omitted counts.

The existing Rust engine runner applies no-new-privileges, inherited network/system-call restrictions, output and deadline limits, and scratch monitoring. The native decompiler inherits that execution context and the durable owner. A successful decompilation additionally requires a real observed native child and verified cleanup before a successful observation is accepted.

For revision 4, `decompilation_performed` describes only the explicit selected-function
operation, as specified by `decompilation_scope=explicit_selected_function`.
Default auto-analysis may itself invoke native decompilation during functions
or xrefs; `auto_analysis_may_decompile=true` preserves that distinction. Helper
records retain PID, start instant/ticks, command, first observed phase and final
state. Roles inferred from timing and executable names are labeled as inference.
Phase-boundary observations are not a complete process-birth history; zero
observations do not prove no helper ran.

After analysis-manager, selected DecompInterface and Program release, the private
JVM owner checks all remaining observed helpers. Before each signal it rechecks
PID, start identity and current JVM ancestry. TERM is followed by one shared
two-second wait; still-owned live helpers may receive KILL followed by a second
shared two-second wait. Original /proc identities must be absent or replaced by
a different start identity; zombies and unknown final states fail. A final
descendant census must be empty. Cleanup failure suppresses success output and
is attached to any existing error. This fixes the observed passive-wait failure
for a persistent GNU demangler without removing the native-child exit gate.

These controls retain existing limits: Ghidra/JRE paths are checked installed paths rather than sealed execution snapshots; selected JRE hashes do not attest every system shared library; scratch is sampled every 250 ms rather than governed by a hard filesystem quota. Interruption can leave private scratch, whose path is retained for operator cleanup. The qualification harness removes only its own confirmed-terminal scratch.

## Meaning of the result

Reports retain raw engine JSON and bounded selected-field summaries. They set `source_semantics_validated=false`, `rea_evidence_compatible=false` and partial coverage. A digest of decompiled C establishes the identity of what Ghidra returned; it does not prove equivalence to the original program. An independent finite-input differential check is retained for the authored qualification fixture only.

This addition does not establish complete upstream REA tool parity, an upstream Evidence conversion, every architecture, macOS/Windows provider execution, isolated-host execution or production deployment. Existing source-only/replay controls and profile policies still apply.

## Reproduction and evidence

The development harness is `tests/rea_ghidra_analysis_external.py`. It compiles owned C fixtures, obtains symbol entries and call sites independently using GNU `nm`/`objdump`, and then uses the real MCP provider through the original durable owner. It checks revision 2 dynamic-ELF inventory, all four analysis operations, same-request replay, controller restart, changed-key-content refusal, invalid/interior selectors and cancellation while the actual native decompiler is live. The observed original Java/native PID start identities must disappear after cancellation, and replay must retain the same original job.

Run only against an explicitly authorized development host with the configured local-SSH/user-systemd mode:

```sh
python3 tests/rea_ghidra_analysis_external.py \
  --runtime /absolute/path/to/hepta-runtime \
  --java-home /absolute/path/to/jdk-25 \
  --ghidra-home /absolute/path/to/ghidra_12.2_PUBLIC \
  --workspace /absolute/new/private/qualification-directory \
  --execution-mode operator --allow-local-ssh
```

The harness requires a fresh directory. It preserves qualification results and raw original jobs rather than replacing a failed receipt. The checked-in evidence index is [qualification](../qualification/rea-ghidra-analysis-20261104-r1/README.md). Exact source/binary hashes and commands distinguish standalone Java API preflights, real-provider execution and finite C differential tests.

For the 12.1.4 comparison, select `--engine-version 12.1.4`, its matching `--ghidra-home`, and the mandatory `--release-archive /absolute/original-release.zip`. The default remains revision 3; select `--bridge-revision 4` explicitly for the new contract. The revision-4 harness compares entry and interior `function`/`xrefs`/`decompile`, records the separate external inventory, and retains full invalid-selector/conflict `CallToolResult` objects before asserting refusal. To reuse the exact original-provider input, supply both `--fixture /absolute/original-owned.elf` and `--fixture-sha256 <64-hex-digest>`; the harness verifies and copies those bytes instead of recompiling the main fixture. The cancellation fixture remains separately authored and identified. Original REA and native results, remaining post-script differences, errors and cancellation observations require separate paired evidence; the harness's finite native checks alone cannot establish parity.

Implementation files are `src/mcp/rea_ghidra_contract.rs`, `rea_engine_profile.rs`, `rea_engine_ghidra.rs`, `rea_provider.rs`, `rea_static_summary.rs`, and the explicitly versioned Java bridges. Contract regressions live in `rea_ghidra_contract_tests.rs`, `rea_provider_tests.rs` and `rea_static_tests.rs`.
