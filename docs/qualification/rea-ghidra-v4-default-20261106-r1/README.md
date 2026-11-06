# Fixed 12.1.4 default-profile diagnostics

These are finite Java/API diagnostics and retained failures supporting the explicit revision-4 profile `hepta.ghidra.12.1.4.elf-x86_64-default-functions.v1`. They do not qualify a Rust MCP binary or establish complete original REA Evidence equivalence. The source was subsequently frozen for a separate real-provider run.

## Actual sequence and boundaries

| Observation | Source and result | What it establishes |
| --- | --- | --- |
| `default-control-r1` | Diagnostic bridge `29563ec9819db2ea39a4b1e172eea9cd20241047daf3c1e993f8ca20083ddad7`; one functions analysis, exit 0 | Real fresh default options; 13 internal and 2 external functions; the stated six-field inventory projection equals all 15 original rows. |
| `default-candidate-r2` | Candidate bridge `655c14efeb7d2bc4f7324419c0355fd5f20a239b079505fc6f2c2f136b198b4a`; functions and interior xrefs succeeded, interior decompile exited 1 | The passive all-descendant `ProcessHandle.onExit()` wait failed with a retained `TimeoutException`. Its empty stdout, stderr, PID and terminal result are preserved. |
| `default-cleanup-r3` | Bridge `25265dc7798a0ef6fe1a0c8aca1ea1d5db53a514c2f5fe2426aa05827730be69`; one additional interior decompile, exit 0 in 10.6468 seconds | Actual C result plus observed native helpers and identity-bound owner cleanup, followed by independent `/proc` absence observations. |
| Later GPL binding | Read-only observation at `2026-11-06T16:24:45.404237+00:00` | All 3,139 admitted installed files matched the pinned release ZIP. This was after the API call; it does not retrospectively upgrade the earlier 3,002-file before/after checks. |

The default control recovered the two identities missing under the earlier four-analyzer candidate: external `EXTERNAL:0x2` and memory thunk `0x405008`, both named `<EXTERNAL>::__gmon_start__`. `inventory-projection-diff.json` enumerates exactly the compared fields: address, name, external flag, thunk flag, thunk target and symbol source. It is a projection comparison, not a complete Evidence comparison.

## Fixed inputs and options

| Identity | Value |
| --- | --- |
| Owned ELF | 15,680 bytes; SHA-256 `ec301f409d22314b43b4392fa80ada28213cd75ca77c6cbbbbfe1454555dd64a` |
| Ghidra release | 12.1.4; release ZIP SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` |
| Java | JDK 25.0.5+8; launcher SHA-256 `1bf1aaef01e4f8d7c85d913c60fb2ee4624cbe54d4053254c59657b7ea913b25` |
| Language/compiler | `x86:LE:64:default` / `gcc` |
| Canonical options | 146 options; SHA-256 `a5531d741cf6e4e42215ea1f4268049600b80c3a03ab7d3586bd3a7bbb7acd75` |
| Selected function | Requested `0x401107`; resolved entry `0x401106`; complete body range `0x401106..0x40111f`, 26 bytes |
| C result | 63 bytes; SHA-256 `f5cfb8e45b727b130ef92c6511118695d2454bf9be1b340c66170611d125d029` |

`analysis-options.canonical.json` is the exact array substring retained in the diagnostic's raw stdout, not a reserialization. Its canonical format is `hepta.ghidra.analysis-options.key-type-class-value.v1`. The adjacent pretty file is a reading aid only. The fresh defaults enable 26 analyzers and disable four; both observed Max Threads options remain 2. No blanket enable, disable or thread override was applied.

The original npm 6.8.0 profile declares `ghidra-default`; the retained launcher applies analyzer overrides only when the disabled-analyzer list is nonempty. Its complete historical option snapshot was not directly sampled. Matching that original configuration to this fresh snapshot remains an inference supported by the retained original profile, configuration and actual npm source. The original post-script differs: `ReaGhidraNoReturnFix` is not applied by the native profile. The retained original log reports `cleared=0 sites=0 refit=0` for this fixture only; no general no-op claim follows.

## Helper ownership and cleanup

The failed candidate waited for every JVM descendant after disposing only its selected decompiler interface. The corrected bridge releases the analysis manager, selected interface and Program before cleanup of actual descendants owned by its private JVM. Every signal rechecks PID, start identity and current ancestry; all helpers share bounded TERM and KILL deadlines. Zombie, unknown or remaining original identities fail the operation.

In the successful API call the GNU demangler was observed as PID 853335/start tick 105928523 and received TERM after Program release; final state was absent. The native decompiler PID 853434/start tick 105928604 was already absent after library disposal. The wrapper independently found both original `/proc` identities absent after JVM exit. Full observations, commands and timestamps are in the raw receipt and stderr. Helper roles are explicitly inferred from phase and executable name; phase-boundary observations are not a complete process-birth history.

The report's `decompilation_performed` field applies to the explicitly selected function only. Default auto-analysis may also invoke a native decompiler. The report and validator preserve this scope rather than implying that functions or xrefs ran without all decompilation.

## Installation boundary

The late release binding covers `Ghidra/` and `GPL/`: 3,139 files, 691,150,237 bytes, including 137 GPL files. The resulting manifest SHA-256 is `f9726184ffcf1a3f9c192e93de04d66e1796b166ead8b3c1f0818559656fcdbe`. The required GNU module and Linux x86_64 native helper are explicitly pinned; GPL JARs do not enter the approved classpath. The real MCP harness must perform this expanded check before and after execution under its own runtime/profile identity.

## Files

`raw-evidence.tar.gz` retains raw source snapshots, launch/terminal records, stdout/stderr, original operation/profile/configuration records, the owned input, the failed and successful receipts, the frozen source manifest and the later GPL binding. `evidence-manifest.json` records every archived path, byte count and SHA-256. `receipt-index.json` records the archive identity and qualification limits. No installed engine or JDK distribution is included.

The historical eight-call, four-analyzer API result remains [separate](../rea-ghidra-v4-api-20261106-r1/README.md). Complete raw original/native field differences and real MCP lifecycle outcomes belong to the later binary-bound evidence; they must not be inferred from this API preflight.
