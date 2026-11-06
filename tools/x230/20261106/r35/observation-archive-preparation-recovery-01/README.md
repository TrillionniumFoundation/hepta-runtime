# R35 first ordinary OBS archive — recovered preparation

This package prepares an immutable archive of the first completed R35 ordinary observation, captured before normal lifecycle launch. The candidate remains based on accepted R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`. Qualification, exact native CI, an observation gate, and final adoption are separate facts. This preparation does not run a measurement or establish adoption.

## Recovery identity

The local execution environment became unavailable and its former temporary files were absent when execution returned. The unavailable first collector draft was 44,136 bytes / SHA256 `ff42a4c1acbd80ccbc32d958334e0d8bbc85bd4670da4593e80f11ab6b029a39`; its sealer was 13,966 bytes / `dc2550252179c7267cd6258a5277cc41363fb23ba3c75f7a0659181cfd6daeb9`. Those original bytes were not recovered and are not represented by this revision.

This new revision was reconstructed from the exact published R34 observation collector that successfully produced observation-evidence-02 and the original R34 sealer. Both reference files were checked against their Git blob identity, byte length and SHA256. Current R35 prerequisites were recovered from Git and bound to actual R35 installation and qualification receipts. The new source and sealer were preserved as Git content blobs before further local preparation.

- Collector: 45705 bytes / SHA256 `96fa3ff43180ec0e922c4b6373ec9d7a902037d97ae06d9a774ebf318d9f1f2c` / Git blob `9c8aa6975766d2119da660c5ce0bf37b9d46f9a4`.
- Sealer: 14857 bytes / SHA256 `68da4d0cc7ceda00e6487e8c8aa24fce8bbb3eb1b7dcf28dde1c214a441f6429` / Git blob `0904d83c6080d2749d287b3666d77ddd038ca548`.
- Original R34 collector reference: 64,408 bytes / `bcd3bc3f0e9606d94be8bbbe45f719dbe4798a540e95f9ca596362f8d4d89f32`.
- Original R34 sealer reference: 12,650 bytes / `331aaa8ed8e60b0e6df8f607780455d58b8a7a796b5c73cbf0a6d9c05c6736a3`.

A local command that attempted to materialize all recovery files at once was rejected before process creation because its argument list was too long. Separate create-only file writes then succeeded. Neither operation started a collector, benchmark, original auditor, test or remote workload.

The R35 OBS postflight revision 02 was independently restored exactly: 15,998 bytes / `6db941beabb85baa7e6b25cf193a46cba5bb27620c392579ef5bfad2ed75c1e0`, Git blob `5fc34284ccd48902b91d2276b5a3c11da9b2a207`. Its original body is distinct from its later actual-pins sealing.

## Selection and immutable inputs

The collector requires 81 static inputs and 29 dynamic originals, with one shared name: 109 unique required members. It selects `campaign-01`, `tools-01`, `boundary-tools-01`, and `lifecycle-tools-01`, together with the original R16 measurement/boundary tools and R35 cancellation-recovery output. The absolute R35 and R16 roots are fixed in source. No arbitrary source directory or output directory is accepted.

The static input provenance records each binding. Twenty-five current R35 original bodies were fetched from Git and independently checked for byte length, SHA256 and Git blob SHA1. Remaining constants are bound to the actual R35 installer receipt or the published, successful R34 collector's unchanged shared-protocol inputs; this recovery does not claim that every such body was freshly downloaded. Collection must rehash the actual selected files against every static pin.

The three R35 materialized lifecycle identities are taken from the actual R35 installer receipt:

| File | Bytes | SHA256 |
|---|---:|---|
| lifecycle-tools-manifest-01.json | 4,066 | eb50cd7ab0376c4b3dc768e8d184fdc23eeaa90c2ce5bdd4b9e9ac551448504e |
| run_lifecycle_abba_01.py | 14,787 | e01357cfb04f72f1ee1d56747df81b572e55c1528d2941f8dbbb0aa5e9a2ac84 |
| run_six_host_cancel_recovery_timed.py | 30,163 | 54186d9750952061b54b255a509848ce72a252d676f584dd288edd263883c0d8 |

The original full Q archive is referenced by SHA256 `a40f7d42c4c17bad59e81f07736ba6999f66d35973ce8c62c9655b9d88476b3a`; the original exact CI archive by `f5f569ccd51d3f2f8cdb11aee115967f0df367a04cf0fd9f50c21a8b5d86d42f`. Their case-log inventories and retained test executables are not duplicated here. Neither archive body is claimed as rehashed by this recovery revision.

R34 archive-failure and diagnostic requirements were removed. They describe an actual earlier R34 preparation failure and remain in the R34 publication. They are not R35 events. R34's deferred custom capacity component is also outside this R35 collector.

## Bounds and verification

The reference limits remain 64 MiB selected total, 8 MiB per file, 2 MiB for the manifest, and 8,192 files. Compressed outputs and bounded expanded tar data are checked separately by the original code. Files must be regular, single-link, canonical-path inputs; reads use NOFOLLOW and stable before/after metadata. All outputs are create-only.

Source trees, target/cache trees, retained test-binary directories, profiles, credentials and runtime executables are excluded. The reader may inspect a file's first four bytes to reject ELF content; it does not archive or execute ELF programs. Verification reads archive members in memory and extracts no files.

The independent local static check parsed Python syntax without importing target modules. Nine original collector functions are unchanged after current-version normalization. Collection and verification only add the first sealed-input guard; creation additionally changes its new output basename to observation-evidence-01. Nine sealer helper/main functions are unchanged after version normalization. Summary reconciliation and the actual-binding portion of sealing are the deliberate semantic changes. The four collector entrypoints first require a complete ACTUAL binding.

## Future results and the pre-lifecycle snapshot

The template has `ACTUAL = None` and refuses use. Its sealer requires these six actual local originals:

1. parent-report.json
2. summary.json
3. observation-holder-native-01.json
4. observation-holder-read-01.json
5. observation-holder-report-01.json
6. observation-postflight-01.json

The original parent report, summary, raw native/read streams, and postflight provide all 29 dynamic identities. Contradictory identities, missing values, changes to a static input, incomplete holder streams, or a postflight outside the first pre-lifecycle scope are rejected. Sealing changes only the ACTUAL assignment; a reverse AST comparison enforces that boundary.

The ordinary observation can pass or fail its original performance gates. Throughput, p95, CPU, RSS, rejection reasons, monitor sample count, and native audit counts are carried from actual originals. A false RSS performance result remains a valid boolean outcome. No C8 rejection, fixed monitor count, future success, or lifecycle outcome is predicted.

This version requires the complete original ordinary workflow and original correctness/evidence closure. It does not synthesize missing core reports for an interrupted workflow. The collector preserves reported values and explicit binding errors, including any namespace conflict observed during collection.

The postflight and sealer describe `normal_lifecycle_state = not_started_at_capture`, using an explicit coordinator nonlaunch source and all five actual lifecycle paths absent. The three output paths and two hypothetical materializer receipt paths are checked. No failed lifecycle native result is invented. Final lifecycle, ABBA performance and saturation results remain null. A later lifecycle run needs its own actual evidence and final adoption decision.

## Operator steps

After the actual postflight original has been obtained, run this sealer locally with an existing originals directory and a fresh output directory:

```sh
python3 -B seal_collector.py --originals /absolute/originals --output /absolute/new-sealed-01
```

The intended remote deployment path for the resulting sealed collector is:

`/home/qian/hepta-runtime-optimization-20261106-r35/observation-archive-tools-01/archive_r35_observation.py`

After the coordinator reviews and installs that exact sealed source, the original single collection invocation is:

```sh
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261106-r35/observation-archive-tools-01/archive_r35_observation.py --kind observation
```

It creates only `observation-evidence-01.tar.gz`, `observation-evidence-01.manifest.json`, and `observation-evidence-01.compact.json` under the fixed R35 root. Existing outputs are not overwritten. The exact same sealed source verifies a downloaded immutable archive:

```sh
python3 -B archive_r35_observation.py --verify /absolute/observation-evidence-01.tar.gz --expected-sha256 ORIGINAL_REMOTE_ARCHIVE_SHA256
```

None of those collector or verification invocations was performed by this preparation. All x230 and Mac actions remain with the coordinator.
