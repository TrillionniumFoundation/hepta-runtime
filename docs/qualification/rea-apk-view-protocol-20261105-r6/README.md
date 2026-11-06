# REA APK, export and retained-view protocol evidence — r6

This archive preserves actual public MCP observations, the prior failed run, and the narrow retained-view input component. All operation receipts keep `qualified: false`. Passing these finite cases does not qualify the complete frozen REA operation or its 229-tool catalog.

## Frozen producer identities

| Run | Immutable native binary SHA-256 | Bytes | Actual result |
| --- | --- | ---: | --- |
| r5 APK/export | `1e76fb57915d1e4c93792528c84b156fdeefd87e18ddd00dfa72f6d2e254a192` | 472,225,816 | 354/378 comparisons passed; 24 failed |
| r6 APK/export and path aliases | `95f40474128b2f6284be7d0cfef4c6169f8123e7737e2e22ba88b819329087fa` | 472,639,624 | 378/378 and a separate 8/8 passed |

The r6 build receipt SHA-256 is `4c953c878660ca99c7211d13f2f26323a1240666d1a99647757309c3083ec85b`. Its source-checkpoint receipt SHA-256 is `cfa4f18a16010d46597e91f50e14371a2d96a0ab9eeb40466452f5c07d499cb0`, recording the 765-file source digest `5088017c5a1af6e4ece7f7bc7ed168f8fb9ec0099c7ed053f33b1ebee0ae3c45`. These original receipts are included verbatim. The behavioral runner authenticates the executable and preserves the supplied source/build receipts; it does not substitute a hand-written successful source attestation for independently checking their complete build chain.

The original producer is `rea-agents@6.8.0` from `https://github.com/morluto/rea`, frozen upstream commit `93b8b82db70279e40f484114cff9dc1958dc14ee`. The complete installed package is checked against the retained tarball before and after each run. The tarball SHA-256 is `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`. Node is v22.23.4, executable SHA-256 `94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90`. Installed transitive dependencies are external trusted inputs, not an asserted independently authenticated package closure.

## The unchanged 378-comparison gate

Both actual producers execute the same inputs in the same order against the same private filesystem paths. The producer implementation is commit `0c512d047795af385af5d73c123788e26f1deb61`; its script SHA-256 remained `cbeed73f0592383d062f201feef894fdccf28f664b219baf6e4bb81ec2e3756b` for both runs.

| Group | Comparisons | Contract exercised |
| --- | ---: | --- |
| APK schema and missing-file inputs | 297 | Actual SDK errors, number spelling, null/type/default boundaries and property order |
| APK complete typed failures | 25 | Complete projected errors, including the 512 MiB + 1 byte admission boundary |
| APK positive results | 16 | Full parent/derived Evidence and independent semantic identifiers |
| Export inputs and file behavior | 23 | 18 schema rejections and 5 actual filesystem behaviors |
| Session flows | 7 | Parent plus derived retention, complete bundle, exact canonical export bytes and unchanged retention after export |
| Registration fields | 9 | Actual input/output schemas and annotations for the three mapped tools |
| Cold session | 1 | Full empty-bundle envelope and new-session isolation |
| **Total** | **378** | **Finite operation profile only** |

MCP JSON text content is parsed into JSON values, so JSON object insertion order alone is not a mismatch. Non-JSON strings remain exact. No path, provider, semantic identifier, diagnostic, `_meta`, `resultType`, or other response field is removed. Export files are preserved byte for byte before the runner removes only its own verified output files between producers. The final nonempty bundle is compared with all observed complete records and with the actual exported payload.

Both original process requests retain the same outer 900-second bound, without a CPU or memory limit and with nice 0. Each request uses the existing 30-second response bound; normal EOF/ownership drain retains its 15-second bound. Neither run silently relaxes those thresholds.

### Original r5 failure remains a failure

Job `1a1a995c1f9-fc05-3626` completed with exit 1, non-timeout and complete durable output. Exactly 24 of the 25 error fixtures differed; the file-size boundary was already equal. All other 354 comparisons passed. The 24 independent native oracle failures identify exactly the same 24 error fixtures; there were no unexplained independent failures or execution errors.

The differing fields were original diagnostic `reason`, `message`, the first structured issue's message, and three remediation actions. Codes, categories, retryability, declared limits, registration, metadata and `resultType` were not masked. This preserved receipt has SHA-256 `1bbf545d8dd37a1a20832d36aeffc3ff2ef2d839bdf12119bf7d9d1420dc207f`.

### r6 closes the observed 24 failures

Job `1a1a9a2be17-fc05-366f` completed with exit 0, non-timeout and complete durable output. All 378 comparisons and all independent checks passed with the unchanged producer and fixture hashes. Receipt SHA-256: `f6900549f9237b66859972033e541212b6976f09c24722c4df39128bea261deb`.

Both binary and reference identities stayed unchanged. The producer-source monitor observed zero events and zero coverage errors. The original/native main and cold sessions all exited naturally after EOF with exit 0, pidfd exit, reader stop and no remaining process group; forced cleanup was empty. This proves those observed shutdowns, not arbitrary cancellation or dropped-future safety.

## Separate path-sensitive retention sequences

The original-only reference job `1a1a99c5537-fc05-3652` captured two fresh sessions. Each performed:

1. Complete inspection of A.
2. Default summary of byte-identical B, or of the literal `/./A.apk` path.
3. Complete inspection using that selected path.
4. Complete retained bundle.

The public operation preserves the chosen display path in `subject.local_path`, `parameters.path` and `normalized_result.artifact.path`. The latter participates in Evidence identity. Consequently A and B, or A and its literal dot alias, produce **different parent IDs**. Each final bundle contains exactly three full records: the first parent, the selected-path parent, and derived summary Evidence linked to the selected-path parent. An error from manually rebinding only an old record's subject is not evidence that this ordinary public sequence fails.

The new independent producer is commit `508c155a902413088bec95d8d87ce14b9c633382`. Four producer tests reject normalized paths, a validly rehashed child linked to the wrong parent, and missing/changed retained records. Actual dual job `1a1a9a5aab7-fc05-3682` then passed all eight complete response comparisons and all four independent path/identity/retention checks on native-r6. Both result envelopes and the remaining JSON-RPC envelope members are compared. No paths or IDs are normalized.

Actual receipt SHA-256: `628dd392c9930fae64867500226cdc78c01ea932722761c231a58c342a132b73`. The original-only reference SHA-256 is `2c786f3f7287a3deecceb6d614014ccd70749353a0273ba04ddfe341a6177039`. All four original/native sessions ended through the same normal EOF ownership checks.

## Analysis-view input component and original behavior

The actual original reference job `1a1a990ba9c-fc05-3609` preserved 50 input/result cases, actual catalog schemas, JavaScript root/source/view key order, raw wire, seed record and exported bundle. Goldens SHA-256: `b4d7e063fc9a97bdd356d5817c95cc5df8057e33ca2d78a0022b4543ee7dbd46`.

The component source/test commit is `52284f09e09d93a4d43c6d605b6e7626d7fb2181`. Its production SHA-256 is `996085ecc5abb352825911efb6e172c196e90e92aaec2b529de8f3b23717b884`. Three targeted Rust tests and strict all-targets Clippy passed in job `1a1a99ea124-fc05-3660`, using locked dependencies, Rust 1.95.0, offline mode and a private target.

This component validates outer `retained-evidence`, `inline` and `evidence-file` sources, summary view and the three APK collections. It reproduces the original structured AnalysisInputError format; it does not reuse APK's aggregated SDK diagnostic format. The 50 cases break down into 35 exact structured errors, 11 accepted outer shapes, and 4 explicitly deferred inline Evidence bodies. Separate tests keep all 37 other recognized view kinds as capability gaps and prevent incomplete private key-order hints from authorizing unknown fields.

`Supported` means only that these supported outer fields passed validation. Actual retained lookup, file capture and Evidence authentication remain separate. `InlineEvidencePending` never claims that a nested record was authenticated. The component is not an integrated qualification of `inspect_analysis_view` on native-r6.

The original reference distinguishes unavailable retained IDs (`evidence_integrity_mismatch`), malformed or tampered inline records (structured input issues), filesystem reads, and unavailable selectors in a bundle. Their full responses remain in the archive.

The failed first reference attempt is retained: it guessed the nonexistent kind `inline-evidence` and stopped at preflight before any behavior cases. The first component run passed its tests but failed one Clippy `question_mark` lint; the original source and logs are kept. The final change was the equivalent `?` form, followed by the same tests and Clippy. Neither failed attempt is counted as a successful behavior gate.

## Qualification boundaries

All receipts remain OPEN or FAILED, with `qualified: false`. This archive does not close full format/error/capacity coverage, arbitrary active cancellation, worker deadlines, external filesystem/platform semantics, generalized retained-view recovery, full build-source attestation, or all REA tools.

The prior r4 oversized-response counter mismatch remains in `docs/qualification/rea-operation-protocol-20261105-r4/`. A separately tested encoding component is not a substitute for rerunning its actual MCP gate after integration. Known remaining malformed-Zstd diagnostic differences are not deleted.

## Archive integrity

`proofs.tar.gz` stores original bytes, including each retained request/response/wire, logs, original job request, authoritative SDK terminal text, source/schema hashes and reference inputs. `manifest.json` records each member's original source, length and SHA-256. Creation reads every tar member back and compares its bytes with the original.

Executables, Cargo targets, private runtime state and generated workspace blobs are not duplicated. Their identities and deterministic fixture constructors remain recorded; the small original analysis-view bare-record and bundle files are included explicitly. Current producer/component sources are included with their commit and SHA bindings.

Archive creation runs no new behavior tests and does not change integration source, production budgets or existing qualification results.
