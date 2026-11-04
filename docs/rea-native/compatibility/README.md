# Frozen REA 6.8.0 compatibility inventory

This directory records the exact published 229-tool catalog in 18 source families and its relationship to the native runtime. An inventory check is not a behavioral qualification. Every upstream operation is still OPEN; the strict parity gate deliberately returns exit status 3.

## Local CI mapping check

The head and prospective-merge CI jobs run this check without a downloaded artifact, desktop cache, Node/npm, provider or network access:

```sh
python3 -B tests/rea_compatibility_ledger_tests.py -v
python3 -B scripts/rea_compatibility_ledger.py check-mapping
```

`check-mapping` verifies the committed 229 ordered tool names and their published name digest, the 18-family inventory, and a separately pinned immutable catalog projection. That projection includes the name, index, family, declaration paths, schema fingerprints and annotations. Its SHA-256 was obtained by regenerating those fields from the authenticated raw catalogs and pinned Git declarations. The check also discovers every native `rea_*` handler and REA CLI variant, verifies source/test content hashes, and recomputes all mapped scope, dependency, gate and OPEN qualification fields from MAP and ENVIRONMENT. Changing a row to PASS, hiding an added handler, or leaving the generated ledger stale fails the check.

The success result deliberately says `mapping_check: PASS` and `raw_reference_authenticity: NOT_REVERIFIED`. It establishes repository consistency with a previously authenticated snapshot; it does **not** read or reauthenticate the original schemas, npm tarball, upstream source bytes or behavioral oracle. The normal CI gate does not depend on the expiring Actions artifact described below. Runtime commit metadata records the sampling baseline only; the gate binds file contents and never requires the current Git HEAD to equal an embedded commit SHA.

## Reproduce full input authentication

Run from the repository root, using a development cache outside the checkout:

```sh
python3 scripts/rea_compatibility_ledger.py restore --cache /absolute/rea-reference-cache --gh gh
python3 tests/rea_compatibility_ledger_tests.py -v
python3 scripts/rea_compatibility_ledger.py generate --cache /absolute/rea-reference-cache
python3 scripts/rea_compatibility_ledger.py check --cache /absolute/rea-reference-cache
python3 scripts/rea_compatibility_ledger.py check --cache /absolute/rea-reference-cache --require-parity
```

The last command is expected to return 3 while any tool lacks full behavioral evidence; this also applies to `check-mapping --require-parity`. Input, source, mapping or stored-ledger inconsistency returns 2. `generate` and `check --cache` retain the full raw-reference and pinned Git-byte verification and report `raw_reference_authenticity: VERIFIED_AGAINST_PINS`. A normal check returning 0 establishes only the inventory invariant. The generator never launches npm, a provider, an instrumented target or a model.

`restore` requires ordinary GitHub artifact/repository read access. It downloads artifact 13194916757 from run 41555825978 and the exact Git blobs named in INPUTS. The artifact was recovered during this run through the GitHub connector after the desktop gh download failed; the recovered archive digest was independently checked. No credentials or signed download URLs are stored here. The Actions artifact expiry was 2026-12-03T00:56:28Z when inspected; preserve the verified cache or re-acquire a byte-identical archive before expiry. A rerun that produces a new oracle must receive new provenance and pins.

The original desktop cache is `/home/qian-qi/rea-ledger-inputs-20261104-r1`, with verified archive `rea-6-8-0-reference-418.verified.zip`, extracted `oracle/`, and pinned `upstream/` sources. The similarly named archive without `.verified` came from the failed gh attempt and is not an input. Large reference catalogs, downloaded packages and executable binaries remain outside the repository. Compact build/runtime qualification receipts are archived under docs/qualification.

## Files and invariants

- `REA_6_8_0_INPUTS.json` pins raw reference bytes, original npm catalog/name digests, the authenticated immutable catalog projection, the exact Git declaration files, additional reviewed corpus sources and the recoverable GitHub artifact.
- `REA_6_8_0_CAPABILITY_MAP.json` is the maintained semantic mapping. Family defaults are overridden for individual upstream tools. A related facility is not counted as an equivalent operation.
- `REA_6_8_0_LEDGER.json` is generated. It contains all 229 names in original catalog order, both input-schema fingerprints, output-schema fingerprints, family/source bindings, native scope, required gates and remaining code/provider/differential work.
- `REA_6_8_0_ENVIRONMENT.json` preserves exact bounded discovery output from seven configured host aliases, durable job identities and selected installation-path observations, then separately records pinned finite observations from the final native release. Its discovery probe source and stdout bytes stay hashed and unchanged. Aliases are not asserted to represent seven independent machines; component parity qualification remains NOT_ESTABLISHED.
- `REA_6_8_0_VALIDATION.json`, `REA_6_8_0_INTEGRATED_VALIDATION_INTERIM.json` and `REA_6_8_0_PREBUILD_VALIDATION.json` retain their historical results. The exact eight pre-update files, including their old ENVIRONMENT and LEDGER inputs, are preserved in the [prebuild snapshot](../../qualification/rea-next-compatibility-prebuild-20261104-r1/). [REA_6_8_0_FINAL_NATIVE_VALIDATION.json](REA_6_8_0_FINAL_NATIVE_VALIDATION.json) retains the later native-only validation. Its complete original input bytes are preserved in the [native-final compatibility snapshot](../../qualification/rea-next-compatibility-native-final-20261104-r1/). [REA_6_8_0_FINAL_MATRIX_VALIDATION.json](REA_6_8_0_FINAL_MATRIX_VALIDATION.json) records the independent completed historical matrix and the full/offline/strict mapping checks sampled at that time. Successful historical Evidence digest replay does not qualify `inspect_elf_notes` or any other complete upstream tool.

The script checks all discovered Rust `rea_*` MCP handlers against the map and refuses an unmapped added/deleted handler. It also discovers REA CLI variants separately, so internal workers and the native browser capture helper cannot inflate the 229-tool count. Optional mapped CLI entries are reported ABSENT until their actual source/dispatch is integrated. The selected-source AST handler maps only part of analyze_javascript_application; lexical scope does not implement semantic tracing, browser URL/import-map resolution or live Electron observation. Update the capability map and regenerate whenever mapped source or contract facts change; the ledger does not silently describe another worktree.

The generator refuses duplicate JSON keys, non-finite numbers, path escapes, byte/digest drift, duplicate archive members, unknown gates and handwritten PASS/equivalent states. Its schema fingerprints use a documented ledger-only JSON encoding. They are not the REA Evidence RFC 8785 canonicalizer. The original npm catalog hash instead preserves the captured JSON number/string tokens and removes only insignificant whitespace.

## Source and package are different identities

Published npm `rea-agents@6.8.0` has 229 tools. The separately pinned Git commit `93b8b82db70279e40f484114cff9dc1958dc14ee` statically declares 234 tools. The five source-only declarations are `guided_workflows`, `inspect_android_jni_bindings`, `read_guidance_section`, `reset_investigation` and `search_guidance`. This is a static source inventory, not an executed Git-build catalog. An equal package version or a later main commit does not establish source/npm equivalence.

## What the environmental observations establish

An existing ADB server reported one XT2551_3 device on pocket4 and the same arm64 emulator identity through mac/main. The probe did not start a daemon, send a device command, attach Frida or select a target. Android hardware is therefore not a proven missing dependency. Per-operation ownership, permissions and reconnect behavior still need qualification.

Desktop has an explicitly observed Ghidra 12.2 launcher, JDK 25 executable and JADX directory outside the process PATH. Chrome/Chromium, GDB/binutils and a pocket4 Apktool installation were also discovered. A discovered path is not a license, compatibility or lifecycle test. JEB/Frida/TShark/Binwalk/Unblob and other selected engines were not found in the bounded PATH/directory observations; that is not a claim that they are absent everywhere. JEB license state remains NOT_PROBED.

Firmware and PCAP corpus work is actionable code/testing work: the pinned upstream includes a Python tar/gzip + host-compiler firmware generator with an independent byte/offset oracle and an owned offline Ethernet/IPv4/TCP capture generator. Provider stubs are explicitly identified and cannot qualify an engine. The observation file links these exact sources rather than inventing a missing-corpus blocker.

## Historical 1d9ea7e native release observations

The desktop executable used for native engine/AST/browser gates is pinned to SHA-256 `4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d` (17,820,288 bytes). Its content-bound source group is `9d08a4cc6b6c89f4db47eb300af5e54dd44092082434c93b1dee954c30b2209a`; the verification group is `b783c4f05a5c7f614ee7150ecc66bb4fe25f1cfd8ed548723e405e4612b6baa4`. The original receipts bind these same inputs before and after the applicable commands.

| Implemented native scope | Recorded final observation | Limit |
| --- | --- | --- |
| Release build | [Four-command build-only receipt](../../qualification/rea-next-release-build-20261104-r2/README.md); release build exited 0 | Does not replace a full matrix or CI run |
| Selected-source JavaScript AST | [Actual normal MCP and independent Babel/manual golden](../../qualification/rea-javascript-final-release-20261104-r1/README.md): MCP 1/1; 17 imports, 16 exports, 12 Electron callsites and 4 candidate edges | Static selected-source subset; no full application graph, runtime Electron/process-pair proof or REA Evidence parity |
| JavaScript worker cancellation | [Stopped-worker MCP cancellation](../../qualification/rea-js-cancellation-final-release-20261104-r2/README.md) observed exit/reap in 0.022742728 seconds within the unchanged 5-second window; same owner stayed alive and recovered; no manual worker SIGKILL | One owned Linux owner/direct worker; the prior v6 negative observation is retained |
| Native Chrome capture | [11 native checks, 10 selected Python-reference pairs and 6 expected deadline checks](../../qualification/rea-browser-final-release-20261104-r2/README.md) on desktop | Fixed owned HTTP resources and saved HAR representation; external Chrome and existing Python durable owner; no arbitrary application recording, process-level network isolation or full HAR/wire equivalence |
| Ghidra revision 2 | [Eight real-engine checks](../../qualification/rea-ghidra-final-release-20261104-r2/README.md), including independent GNU entries/call sites, selected native decompile, restart and cancellation | Ghidra 12.2/JDK25 and the existing Python launcher/owner are external; cancelled scratch cleanup is recorded as harness cleanup; the older 141-input C comparison was not rerun |

These are finite historical observations of the implemented native capabilities. That snapshot recorded **229 OPEN tools**, **0 qualified**, **16 partial operations**, **23 related facilities** and **190 absent operations**. Read the generated ledger summary for the current implementation inventory; later native increments do not retroactively qualify this binary. Required upstream behavior gates are unchanged. Every component's parity field remains `NOT_ESTABLISHED`; native receipts are recorded separately instead of being relabeled as complete operation parity.

The source map binds the selected final receipt files and their archive manifests in addition to source/test contents. The full cached check authenticates the frozen upstream inputs; the offline check only checks repository snapshot/mapping consistency. Neither reruns the native engine/AST/browser receipts. The independent functional matrix below has its own executable and receipts. Remote CI is established only by PR/Actions records tied to the published head and prospective merge SHAs; these local receipts do not claim a CI result. Actual CI outcomes belong in PR text, so no extra compatibility-data commit is needed just to copy CI status. The original desktop 35-command run remains timed out after 34 completed commands.

## Independent completed Ubuntu24 functional matrix

The [original r3 matrix archive](../../qualification/rea-next-ubuntu24-matrix-r3-20261104-r1/r3/sealed/README.md) records **35/35 commands meeting their exact expected exits** on ROG in a fixed-image Ubuntu24 container. The [qualification](../../qualification/rea-next-ubuntu24-matrix-r3-20261104-r1/r3/output/integrated-build-r3/qualification.json), [container owner receipt](../../qualification/rea-next-ubuntu24-matrix-r3-20261104-r1/r3/output/matrix-owner-receipt.json), original durable terminal/witness and all logs are preserved by the original transfer manifest.

| Matrix portion | Original recorded outcome |
| --- | --- |
| Rust all-features | 1886 tests run, 1886 passed, 39 skipped |
| Rust no-default-features | 1861 tests run, 1861 passed, 27 skipped |
| Python | 21 suites, 441 tests; every suite reported OK |
| Full cached / offline ledger checks | Both exit 0 |
| Strict parity check | Expected exit 3; 229 upstream tools still OPEN |
| Container owner | Exit 0, no timeout or OOM kill; container removed |

The ROG matrix built a distinct **17,842,176-byte** executable, SHA-256 `2d021297b50af9eb35bd4d698a90991ec410b2922b707155a506e42125b87442`. The desktop native-engine/AST/browser receipts continue to bind `4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d`. These are different artifacts with identical source group `9d08a4cc6b6c89f4db47eb300af5e54dd44092082434c93b1dee954c30b2209a` and verification group `b783c4f05a5c7f614ee7150ecc66bb4fe25f1cfd8ed548723e405e4612b6baa4`, unchanged before and after the applicable runs. The matrix does not rerun the desktop external-engine gates on the ROG artifact.

The r3 environment reused the r2 Cargo target and whitelisted Cargo home. It corrected the task tmpfs mount to exec while retaining nosuid/nodev and actually executed an owned mode0700 shim before starting. It did not change source, tests, CI, the frozen runner, command argv, expected exits or budgets. The earlier r2 failure stays a failure. This is a functional qualification in that recorded environment, not general bare-ROG support or desktop ext4/power-loss durability evidence.

Historical matrix ledger checks used their original inputs. FINAL_MATRIX_VALIDATION binds that earlier canonical ENV/LEDGER snapshot; later continuation checks are separate observations. Prior PREBUILD and FINAL_NATIVE receipts retain their original input snapshots rather than being silently reinterpreted against newer data.

## Native continuation after 1d9ea7e

The native [ASAR reader and explicit graph acquisition](../ASAR.md),
[source-map declaration/point reader](../SOURCE_MAP.md),
[APK signature-record verifier](../APK_SIGNATURE_NATIVE.md), and
[decimal-halfway Evidence correction](../../qualification/rea-evidence-halfway-20261104-r2/README.md)
carry their own source/binary-bound receipts. ASAR header/selected-member
consistency is separate from publisher authentication. APK v2/v3 mathematical
record verification is separate from complete Android verification, signature
scheme selection and certificate trust. Source-map declarations
and a matching point projection are separate from a full upstream trace tool.
The earlier 418-case numeric corpus did not contain the newly reproduced
halfway ties; it remains pinned historical input, alongside the new 438-case
producer and wider finite-bit oracle. Neither corpus replaces complete
operation-specific Evidence and typed-outcome qualification.

The frozen `inspect_apk_signature` contract is distinct from the general
`inspect_signature` native/platform operation. Only the dedicated APK row maps
to `rea_inspect_apk_signature`; the general platform operation remains absent.
Android apksigner, Java and Bouncy Castle are independent development oracles
for this finite APK validation, not runtime dependencies of the native reader.
The earlier structural mapping check did not prove this semantic distinction;
the corrected map preserves both upstream names and their original contracts.

## Historical npm Evidence replay

The recovered artifact includes 418 finite-number cases, corpus digest `9507bba36f7de741ad9a0100516cdaf0a85b496d11feb34e0b4fd8afe1d755fc`, and the original npm ELF-note Evidence record. These were replayed in native Rust at baseline `310add6db47bcfbed3545432eb528a72f5eb6dcd` using the existing ignored tests. Each filter actually executed one test; both passed. The test loops over the authenticated 418-case input. This exercises the Evidence semantic commitment and selected identity invariants, not all 229 operations.

```sh
REA_REAL_FLOAT_EVIDENCE_JSON=/absolute/rea-reference-cache/oracle/REA_6_8_0_FINITE_NUMBER_EVIDENCE.json cargo test --locked --lib -j4 real_npm_fractional_reference_evidence_matches_native -- --ignored --test-threads=1
REA_REAL_EVIDENCE_JSON=/absolute/rea-reference-cache/oracle/REA_6_8_0_ELF_NOTES_EVIDENCE.json cargo test --locked --lib -j4 real_npm_reference_evidence_matches_native_subset_identity -- --ignored --test-threads=1
```

## Closing an operation

Each generated row separates missing implementation/contract semantics, independent behavioral differential work and, when applicable, selected provider/platform qualification. Code work can proceed while a provider profile is located or qualified. The frozen npm catalogs and source declarations are not substituted for execution. A future qualification runner must bind exact input and native source/provider identity, independently expected facts, outcome/unknown distinctions, Evidence, limits, cancellation, retention and recovery where required. Only such a runner may supply passed gates; editing a status word in this map cannot close parity.
