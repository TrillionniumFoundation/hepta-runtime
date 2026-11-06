# Evidence and APK qualification of the revised merged release

This archive records three unchanged external harnesses executed against the new frozen release after the runtime-only source-map registration and pending-intent test fixture corrections. It is a new run; the earlier `0595fbf…` release evidence in `rea-final-independent-release-20261104-r2` remains historical and unchanged.

## Artifact and execution identity

| Item | Recorded value |
| --- | --- |
| Release SHA256 | `aa580409a73bc2e0927ead93d32634239051a39fc951c3c2a92d5a1dece8347a` |
| Release size | 18,437,864 bytes |
| Frozen source commit | `ed74d9dbf04b97fad38112c2ac08127bf99b3590` |
| Build source tree before and after | `4021ee22efdf2eac830e08afc45eddf37b264e7fd31a222c329b4950ef2d94b6` |
| Original build summary SHA256 | `0541d43b62f631b3ebcda4895bafc5cdc087ac94460780191c0e61a4f043292d` |
| Three-group wrapper SHA256 | `235103132a921ec9f8f313293eac629a486ca3f463b929b117329deea3d73577` |
| Actual gate job | `1a1a7437a8c-fc05-2ac2` |
| Gate interval | 2026-11-04T15:53:02.082215+00:00 to 2026-11-04T15:54:09.821514+00:00 |
| Total elapsed time | 67.739313 seconds |

The wrapper was copied byte for byte. Its three harness hashes, assertions, fixture identities and internal 900-second aggregate budget were unchanged. The complete old and new durable requests confirm the same outer profile: `/bin/sh -c python3 -B …`, no per-job CPU quota or memory cap, nice 0, an empty environment override map, and a 930-second supervisor limit. Only private artifact and output paths, and the release identity, changed. The build and external gates have separate execution profiles, recorded with their actual environment overrides.

The independent binary copies and every one of the 32 selected source, script, configuration and fixture inputs matched before and after. The wrapper executed the original root harnesses with Python bytecode writes disabled, and all working directories and outputs were outside ROOT. Four APK source-hash inputs were copied into a private oracle working directory and checked against the original sources before and after. The root build target was not used by this validation.

## Results

| Gate group | Observed result |
| --- | --- |
| Authentic npm finite-number Evidence over public MCP | **438/438 accepted**, zero unexpected rejections and zero mismatches; controller exit 0 |
| Native APK / original REA / Android oracle comparison | **20 fixtures and 4 malformed worker inputs qualified**; 2,398 installed REA package files checked against the frozen package |
| Actual APK public MCP lifecycle | **6/6 gates passed**; both controllers exited 0, with no manual worker cleanup or controller teardown actions |

The APK set includes 19 genuine signed inputs and one deliberately forged input with a matching content digest. It preserves typed outcomes: the supported 33-bit RSA exponent is verified; both genuine 34-bit exponent fixtures remain partial with unsupported signatures; the forged signature remains invalid; a v1-only input remains absent from the v2/v3 record result.

The public MCP cancellation case used an actual stopped owned worker and its original controller. Cancellation, reap and subsequent-request recovery took **0.021748459 seconds** within the unchanged 5-second observation budget. The fixed production deadline remained 30 seconds; observed completion was **32.369054655 seconds from the request**, and **30.626186646 seconds from observing the stopped worker**, within the unchanged 35-second observation budget. Successful cold-controller reinspection is also retained. No manual cleanup was counted as a pass.

These are the existing cooperative public MCP and worker lifecycle cases. They do not establish arbitrary future dropping of a caller during blocked filesystem reads, or a new filesystem hard-cancellation guarantee.

## Retained preflight failure

The first preparation attempt, `1a1a739537c-fc05-2aa0`, exited 1 at exclusive `mkdir`: another agent already owned `prepared-r2` for the engine regressions. The program failed before copying or replacing any artifact and before launching these gates. Its exact terminal record and 275-byte `FileExistsError` are retained as a preflight event, and it contributes no passed test count.

After its terminal failure and exact error were read back, preparation moved to the owned `prepared-evidence-apk-r2` directory. That separate preparation job, `1a1a7405aaf-fc05-2ab0`, exited 0. The other agent's directory and all historical proofs were preserved. Read-result delivery timeouts were reconciled through immutable background read results; they did not restart any preparation or gate process.

## Evidence layout and limits

`combined-qualification.json`, `evidence-mcp.json` and `apk-public-mcp.json` are exact copies of the completed harness receipts. `apk-oracle-summary.json` is explicitly a compact projection of the original APK report; its full original file and SHA256 remain bound in `artifact-manifest.json`. Build, preparation and durable job records are retained separately. The manifest also binds the exact original outer resource request, source/scripts, fixtures, npm corpus and original full reports.

All full outputs remain at:

`/home/qian-qi/work/hepta-rea-final-independent-20261104-r2/gates-r2`

The independent prepared copy and build provenance remain at:

`/home/qian-qi/work/hepta-rea-final-independent-20261104-r2/prepared-evidence-apk-r2`

This archive qualifies the finite Evidence corpus, bounded APK signature-record behavior and the six stated public MCP lifecycle gates. It does not qualify complete upstream Evidence schema/view/retention parity, full Android installability or trust semantics, every APK signing scheme, the complete Rust matrix, or full REA parity. The recorded full-parity and full-Android flags remain false.
