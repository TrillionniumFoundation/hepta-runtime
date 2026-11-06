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

The original desktop cache is `/home/qian-qi/rea-ledger-inputs-20261104-r1`, with verified archive `rea-6-8-0-reference-418.verified.zip`, extracted `oracle/`, and pinned `upstream/` sources. The similarly named archive without `.verified` came from the failed gh attempt and is not an input. Large catalogs, packages, binaries and build logs remain outside the repository.

## Files and invariants

- `REA_6_8_0_INPUTS.json` pins raw reference bytes, original npm catalog/name digests, the authenticated immutable catalog projection, the exact Git declaration files, additional reviewed corpus sources and the recoverable GitHub artifact.
- `REA_6_8_0_CAPABILITY_MAP.json` is the maintained semantic mapping. Family defaults are overridden for individual upstream tools. A related facility is not counted as an equivalent operation.
- `REA_6_8_0_LEDGER.json` is generated. It contains all 229 names in original catalog order, both input-schema fingerprints, output-schema fingerprints, family/source bindings, native scope, required gates and remaining code/provider/differential work.
- `REA_6_8_0_ENVIRONMENT.json` holds exact bounded discovery output from seven configured host aliases, durable job identities and selected installation-path observations. Its probe source and stdout bytes are hashed. Aliases are not asserted to represent seven independent machines.
- `REA_6_8_0_VALIDATION.json` contains the actual scoped verification receipt. Successful historical Evidence digest replay does not qualify `inspect_elf_notes` or any other complete upstream tool.

The script checks all discovered Rust `rea_*` MCP handlers against the map and refuses an unmapped added/deleted handler. It also discovers REA CLI variants separately, so internal workers and the native browser capture helper cannot inflate the 229-tool count. Optional mapped CLI entries are reported ABSENT until their actual source/dispatch is integrated. The selected-source AST handler maps only part of analyze_javascript_application; lexical scope does not implement semantic tracing, browser URL/import-map resolution or live Electron observation. Update the capability map and regenerate whenever mapped source or contract facts change; the ledger does not silently describe another worktree.

The generator refuses duplicate JSON keys, non-finite numbers, path escapes, byte/digest drift, duplicate archive members, unknown gates and handwritten PASS/equivalent states. Its schema fingerprints use a documented ledger-only JSON encoding. They are not the REA Evidence RFC 8785 canonicalizer. The original npm catalog hash instead preserves the captured JSON number/string tokens and removes only insignificant whitespace.

## Source and package are different identities

Published npm `rea-agents@6.8.0` has 229 tools. The separately pinned Git commit `93b8b82db70279e40f484114cff9dc1958dc14ee` statically declares 234 tools. The five source-only declarations are `guided_workflows`, `inspect_android_jni_bindings`, `read_guidance_section`, `reset_investigation` and `search_guidance`. This is a static source inventory, not an executed Git-build catalog. An equal package version or a later main commit does not establish source/npm equivalence.

## What the environmental observations establish

An existing ADB server reported one XT2551_3 device on pocket4 and the same arm64 emulator identity through mac/main. The probe did not start a daemon, send a device command, attach Frida or select a target. Android hardware is therefore not a proven missing dependency. Per-operation ownership, permissions and reconnect behavior still need qualification.

Desktop has an explicitly observed Ghidra 12.2 launcher, JDK 25 executable and JADX directory outside the process PATH. Chrome/Chromium, GDB/binutils and a pocket4 Apktool installation were also discovered. A discovered path is not a license, compatibility or lifecycle test. JEB/Frida/TShark/Binwalk/Unblob and other selected engines were not found in the bounded PATH/directory observations; that is not a claim that they are absent everywhere. JEB license state remains NOT_PROBED.

Firmware and PCAP corpus work is actionable code/testing work: the pinned upstream includes a Python tar/gzip + host-compiler firmware generator with an independent byte/offset oracle and an owned offline Ethernet/IPv4/TCP capture generator. Provider stubs are explicitly identified and cannot qualify an engine. The observation file links these exact sources rather than inventing a missing-corpus blocker.

## Historical npm Evidence replay

The recovered artifact includes 418 finite-number cases, corpus digest `9507bba36f7de741ad9a0100516cdaf0a85b496d11feb34e0b4fd8afe1d755fc`, and the original npm ELF-note Evidence record. These were replayed in native Rust at baseline `310add6db47bcfbed3545432eb528a72f5eb6dcd` using the existing ignored tests. Each filter actually executed one test; both passed. The test loops over the authenticated 418-case input. This exercises the Evidence semantic commitment and selected identity invariants, not all 229 operations.

```sh
REA_REAL_FLOAT_EVIDENCE_JSON=/absolute/rea-reference-cache/oracle/REA_6_8_0_FINITE_NUMBER_EVIDENCE.json cargo test --locked --lib -j4 real_npm_fractional_reference_evidence_matches_native -- --ignored --test-threads=1
REA_REAL_EVIDENCE_JSON=/absolute/rea-reference-cache/oracle/REA_6_8_0_ELF_NOTES_EVIDENCE.json cargo test --locked --lib -j4 real_npm_reference_evidence_matches_native_subset_identity -- --ignored --test-threads=1
```

## Closing an operation

Each generated row separates missing implementation/contract semantics, independent behavioral differential work and, when applicable, selected provider/platform qualification. Code work can proceed while a provider profile is located or qualified. The frozen npm catalogs and source declarations are not substituted for execution. A future qualification runner must bind exact input and native source/provider identity, independently expected facts, outcome/unknown distinctions, Evidence, limits, cancellation, retention and recovery where required. Only such a runner may supply passed gates; editing a status word in this map cannot close parity.
