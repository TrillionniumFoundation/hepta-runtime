# Bounded Ghidra function analysis

This extends the Rust static-provider contract and worker, using the existing durable job owner, with real Ghidra function discovery, selected-function inspection, cross-references and native decompilation. It requires an explicitly configured, revision-bound Ghidra installation and Java 25. Legacy and revision 2 profiles use Ghidra 12.2; revision 3 separately admits the fixed 12.1.4 distribution used for the original REA comparison. Ghidra's Java/native engine remains an external dependency; this is not a Rust rewrite of the decompiler. In the previously qualified 12.2 operator deployment, the existing Python 3 launcher and durable runner start the Rust `rea-static-worker`, which invokes the fixed Java bridge and installed Ghidra native engine. That historical qualification does not transfer to revision 3 or to a newly built runtime.

The existing MCP surfaces remain `rea_static_profiles`, `rea_static_start`, `rea_static_status`, `rea_static_read` and `rea_static_cancel`. There is no second task registry, background service or recovery handle. The complete original request identifies the existing durable job after replay, cancellation or a controller restart.

## Versioned profile and compatibility

`GhidraEngineProfile.bridge_revision` is optional in serialized profiles:

| Value | Engine | Bridge | Admitted operations |
| --- | --- | --- | --- |
| Absent | 12.2 | Original `rea_ghidra_bridge.java`, unchanged bytes | `inventory` only |
| `2` | 12.2 | Repaired `rea_ghidra_inventory_v2.java` or `rea_ghidra_analysis_bridge.java` | Explicitly allowed `inventory`, `functions`, `function`, `xrefs`, `decompile` |
| `3` | 12.1.4 | Separate `rea_ghidra_inventory_1214_v3.java` or `rea_ghidra_analysis_1214_v3.java` | The same explicit operation selection, with independently bound engine and bridge identities |
| Any other explicit value | Refused | None | None |

Absent new fields remain absent when serialized. Existing request/profile identities are therefore preserved. Revision 2 changes the profile hash and selects a different bridge hash. The returned report includes the admitted engine profile and exact embedded bridge SHA-256; a new bridge is never interpreted as the old bridge.

Revision 3 requires engine version `12.1.4` and release ZIP SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`. Legacy and revision 2 still require version `12.2` and SHA-256 `2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67`. Cross-version or cross-revision results are rejected even when a caller recomputes their report digest. Installation manifests, source bytes, Java runtime files and cleanup observations retain their existing validation requirements. Adding a profile does not establish original REA result or lifecycle equivalence.

The original byte-array importer has a real Ghidra 12.2 failure on a dynamically linked ELF: the anonymous byte provider has a null name, and Ghidra's library-name comparator dereferences it even when target-library loading is disabled. Revision 2 passes a fixed named `ByteArrayProvider("hepta-owned-input", bytes)`. No user path or library name is substituted. It retains disabled target-library loading and project linking.

The legacy bridge remains solely to preserve its explicit historical identity and existing receipts. New profiles must explicitly choose the revision matching their fixed installation. Updating a profile does not authorize replaying an uncertain old request as a different job; retain the original profile, request and key for observation of the original job.

## Fixed operations

| Operation | Selection | Result and limits |
| --- | --- | --- |
| `inventory` | Captured ELF | Memory/imported-symbol inventory without automatic analysis or decompilation. Revision 2 also binds observation source SHA-256 and size. |
| `functions` | Captured ELF | Fixed analysis; at most 4,096 internal functions scanned and 128 rows returned, with scan completeness and omitted counts. |
| `function` | One exact internal entry | Entry, qualified name/prototype, body bounds/size and thunk metadata after fixed analysis. |
| `xrefs` | One exact internal entry | Incoming references to that entry; outgoing references from the selected function body. Each direction scans at most 4,096 references and returns at most 128 rows, with scope/completeness/omission fields. |
| `decompile` | One exact internal entry | Real `DecompInterface` native decompilation; completion status, bounded C preview, full C length/digest and preview digest/completeness. Native child cleanup must be confirmed. |

The optional request field `function_address` is required for `function`, `xrefs` and `decompile`, and refused elsewhere. It is a canonical lowercase hexadecimal entry such as `0x401106`: no uppercase, leading zeroes, symbol name, range, space prefix, expression or script. An address inside a function is not silently converted to its entry. If there is no exact internal analyzed function at the selected entry, the real backend fails and no successful mapped facts are returned.

The artifact must be owned, inside the profile's input roots, and match the supplied artifact SHA-256. Sealed captured ELF bytes are used for import; the target is not executed. The worker does not accept arbitrary flags, analyzer names, output paths, plugins or scripts.

## Analysis and resource boundaries

The revision 2 analysis profile is `hepta.ghidra.elf-functions.v1`; revision 3 uses `hepta.ghidra.12.1.4.elf-functions.v1`. Exactly four recognized analyzers are enabled:

- Disassemble Entry Points
- Function Start Search
- Stack
- Subroutine References

Other recognized analyzers are disabled, and their count/name-set digest is reported. Stack analysis is restricted to one thread. This is deliberately a partial analysis profile. It does not claim all Ghidra headless analyzers, debug-symbol loading, language/architecture parity or recovery of every function.

The current bounds are: input at most 8 MiB, analysis monitor 30 seconds, native decompilation monitor 15 seconds, overall configured operation deadline at most 120 seconds, JVM heap 512 MiB and returned stdout at most 64 KiB. Profile admission requires at least 1 GiB memory; the qualification profile uses 1.5 GiB. Installed files are verified against a sealed manifest and their identities rechecked before and after engine use.

Full decompiled C is limited to 1 MiB before previewing. At most 8,192 UTF-16 code units are initially retained, bounded to 32 KiB of UTF-8; fitting the response budget may reduce the preview further. Full/preview digests and `c_code_complete` distinguish those cases. Functions and reference rows can likewise be reduced to fit the response budget, without hiding omitted counts.

The existing Rust engine runner applies no-new-privileges, inherited network/system-call restrictions, output and deadline limits, and scratch monitoring. The native decompiler inherits that execution context and the durable owner. A successful decompilation additionally requires a real observed native child and verified cleanup before a successful observation is accepted.

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

For the 12.1.4 comparison, select `--engine-version 12.1.4`, its matching `--ghidra-home`, and the mandatory `--release-archive /absolute/original-release.zip`. To reuse the exact original-provider input, supply both `--fixture /absolute/original-owned.elf` and `--fixture-sha256 <64-hex-digest>`; the harness verifies and copies those bytes instead of recompiling the main fixture. The cancellation fixture remains separately authored and identified. Original REA and native results, analyzer differences, errors and cancellation observations require separate paired evidence; the harness's finite native checks alone cannot establish parity.

Implementation files are `src/mcp/rea_ghidra_contract.rs`, `rea_engine_profile.rs`, `rea_engine_ghidra.rs`, `rea_provider.rs`, `rea_static_summary.rs`, and the explicitly versioned Java bridges. Contract regressions live in `rea_ghidra_contract_tests.rs`, `rea_provider_tests.rs` and `rea_static_tests.rs`.
