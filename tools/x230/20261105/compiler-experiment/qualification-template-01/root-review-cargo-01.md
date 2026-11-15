# External CPU qualification template: bounded Cargo review 01

**Static review only. No concrete blocker found in the requested Cargo invocation, eight-stage preservation, test inventory, and artifact-path scope. The selected execution branch and actual future release parser remain unverified.**

Reviewed driver: `qualify_cpu.py`, 31,131 bytes, SHA256 `e9dede814f34e414969019408c692da01e3254279440f10d255e32e6454fe2af`. Original qualifier: 7,661 bytes, SHA256 `95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d`. Full inspected file identities are in the companion JSON.

No native call, Rust/Cargo command, build, test, module import, selected-branch execution, network/GitHub operation or archive extraction was performed. Only these two review files were written; frozen inputs, implementation, manifests and local-check results were not changed.

## Findings

| Scope | Result and source |
|---|---|
| Eight stages | `qualify_cpu.py:24-25,427-486` retains format, fmt-check, harness-tests, clippy, test-build, isolated-tests, audit-isolated-tests, release in original order. Full target/feature scope, offline/locked behavior, original runner/auditor, 180-second case timeout and no-retry behavior remain. Stage wrapper retains original subprocess/log treatment with the fixed 3,600-second limit. |
| Cargo/toolchain argv | `274-278,378-387,429-438,467-468`: direct pinned toolchain executables replace the rustup shim and `+1.95.0`. There is no `+toolchain` incorrectly passed to the real Cargo. Explicit `--target` and `-vv` occur before Clippy's `-- -D warnings`; JSON options belong to Cargo. Fresh target/triple output layout is explicitly used. |
| Exact test inventory | `111-145,442-465`: retains every `profile.test` executable without filtering `target.test`; compares full logical target objects after only source-root normalization, exact names and ignored state. Inventory totals derive from the selected accepted reports, not hardcoded R24 totals. |
| Actual audit shape | Original auditor and actual R26 report from that same auditor expose the accessed `selected/passed/failed/ignored`, `expected_filter`, `input_sha256`, and auditor SHA keys. This verifies schema compatibility only; it does not select R26 as a baseline. |
| Release evidence | `311-359`: exactly one successful build-finished and non-fresh expected artifact per original retained product, expected source/manifest/features/release profile, unique final rustc argv, selected CPU/target and O3/fat-LTO/CGU1/panic/strip checks. No fallback to prior output paths or ELF. |
| No invented success | Input stays unselected with future values null. Existing local-validation claims only AST/diff/original-identity/unbound-refusal checks. Future `qualified=true` remains separate from `performance_accepted=false`. |

## Zero-test example is correctly retained

The actual R24 summary is 6,878 bytes, SHA256 `ccf23b817d83bbcd1bee10473fa897739c452b0727d9d85f53d3b593c45d90f1`. Its target inventory is:

| Target | Kind | `target.test` | Inventory | Ignored |
|---|---|---:|---:|---:|
| native_process_driver | example | false | 0 | 0 |
| hepta-runtime | bin | true | 2 | 0 |
| hepta-effect-ownerctl | bin | true | 18 | 0 |
| hepta-runtime-jobctl | bin | true | 37 | 0 |
| hepta_runtime | lib | true | 1,622 | 34 |

These are historical observed counts, not candidate requirements. The zero-case example contributes a logical target even though it contributes no cases. Removing it would change the `targets` equality and fail the comparison. Different future binary hashes and temporary build paths do not change logical identity; each variant still has its own original audit and ELF binding.

## Concrete limits, not pass evidence

The bounded inspected R24 paths contain the native test summary's original Cargo target objects, but no raw original release `-vv`/JSON stream. The original accepted release command did not request either output. A filename-only search for local Cargo/artifact/no-run/release-stderr evidence found no raw stream to use. Therefore this review does **not** establish that the selected compiler's actual verbose format passes the new parser.

The parser recognizes `Running ` commands enclosed in backticks, uses `shlex.split`, and inspects separate `-C` pairs. It accepts `lto`, `lto=yes`, or `lto=fat`, requires one occurrence of each required codegen key, and records actual argv. Missing, ambiguous or differently rendered evidence fails closure. A future real output must remain authoritative; intended recipe flags cannot be substituted for an observed command. No mock future success was created.

The original three retained release products remain the runtime, jobctl and native process driver. `--bins` also builds the automatic effect-ownerctl target; preserving the original retention scope is not a new claim about deploying that artifact. Root independently owns metadata, handoff, current accepted-source binding and live execution coordination. No CPU, triple, baseline or future result was selected here.
