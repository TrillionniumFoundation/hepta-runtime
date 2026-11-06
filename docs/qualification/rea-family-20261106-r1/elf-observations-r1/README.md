# C9 ELF / Evidence original observations and offline replay

This directory preserves the first actual ELF family and lifecycle runs for source commit c9c79e27a2bf56bd204df6591ca2311dc872e317. It contains original proof bytes and separate derived consumer assessments. The source tree SHA256 is e24bfd8dddb62f58b0bcfd6362c17b7ee7677605551f29a65fc98e44b847764f; the Linux all-feature binary is 51,113,816 bytes with SHA256 56ae3b2313122ae7baae46df5536ee41f898aa09cbea10478a72de7cfe74e7cd. The fully passed nine-stage build summary SHA256 is caca443885057c9d7d71251228dd380d22bb7e47d3cdd6706a2eea38b525d6b7.

## Actual results

The ELF family completed all eight owners and all 50 comparisons: **40 PASS, 10 FAIL**. The independent consumer confirms **FAILED / finite FAIL**, qualified=false. All ten failures are differences in the opaque error content[0].text key order. Parsing those strings for diagnosis produces equal error values; this does not make the complete public text equal, and no normalization was used to change the verdict. The exact cases and both original CallToolResults are in elf-family-r1/failure-diagnostics.json inside the family archive.

All seven canonical export-byte comparisons passed, including explicit import in new owners and unchanged state after truncated, tampered, and missing imports. The native-only readback extension completed 53 calls, reconstructed the entire 6,302,590-byte original canonical bundle in 25 pages, kept old snapshot pages stable after new Evidence, rejected invalid/released/cross-session cursors, and restored retained snapshot accounting to zero. The full bundle SHA256 is b6a7eec674c83a9c551144a66d13257eb46068ce2f17a2dc296daf54f570117c. This extension has no frozen upstream Node equivalent. Frozen upstream ELF analysis views remain unsupported.

The lifecycle run completed six owners. Both active acquisition cancellation cases, native worker capacity cancellation with four distinct reaped workers, the 30,000 ms native worker deadline, and both active EOF cases passed their independent checks. The overall assessment remains **OPEN**, qualified=false, because no equivalent original Node parser deadline injection boundary has been established. The lifecycle consumer deliberately leaves its standalone build-source gate OPEN; the unchanged original matrix bundle is also retained here and separately validated against that lifecycle source and binary.

All 14 MCP owners closed normally, with no forced cleanup; original pidfd, process-group, reader and worker observations are retained. These finite Linux results do not qualify the whole operations or alter the operation ledger (0/229).

## Proof archives and relocation

Each .members.json lists every tar member's exact byte count and SHA256 and pins the compressed archive. Family retains all nine required fixture/import inputs. Lifecycle omits its 512 MiB and 32 MiB physical fixture bodies; its independent consumer reconstructs and verifies the deterministic fixture identity from the pinned metadata without opening those bodies. Neither archive contains target binaries, npm, JDK, private controller state, or operator credentials. The minimal generated runtime.json is included because its exact execution configuration is part of the proof.

Both archives were extracted to a different directory and their independent consumers were actually run using the original receipt SHA256. Consumer return codes, stdout assessment bytes, and stderr bytes match the original-directory runs exactly. The family replay reproduces its expected nonzero FAIL; the lifecycle replay reproduces OPEN. replay-summary.json records the original and relocated command arguments and every archive digest. No provider was rerun during archive replay. The raw qualification.json files and execution-path metadata were not rewritten.

## Reproduction

Use a repository checkout of source commit c9c79e27a2bf56bd204df6591ca2311dc872e317, then extract each archive into a fresh directory. Run the repository scripts with that checkout as --repo and the relocated qualification.json path. The exact original execution and consumer argument lists are retained in commands.json. The original report pins are:

- ELF family: f9507225345b65491cfb05f3a280eae2a9c04278b28d624035955efac24a1047
- Lifecycle: 9d6188693ce2d07516215e2fb83c59e41eaff2c4b3d8903fbba6649442aa4a26

The family consumer uses --report; the lifecycle consumer uses --receipt; both require --sha256. Offline proof replay needs the matching source checkout and archived artifacts, and does not launch Node, the runtime, or an analysis engine. The archive's relative artifact locations may move; recorded execution paths remain the original observations.
