# Supplemental cold-session full pager

One fresh native owner completed the missing cold-session full read. The producer and independent consumer both succeeded: **34 tool calls, 25 pages, 6,302,590 bytes through EOF, one normal owner close**. The complete reconstructed bytes and complete re-export each exactly equal the original native `export-full` bundle, SHA-256 `c6517498ecbf04562c50f6a93c66e6fa9f17123df0a645d759df701b61ae8be8`.

This supplements [the original R5 family archive](../elf-observations-r2/README.md), whose cold extension read seven bytes and re-exported the complete bundle. Its original 50 comparisons, 53 extension calls, eight owners, receipt and archive members were not changed. The original six lifecycle sessions are also unchanged. This supplementary result is native-only and remains `qualified: false`; it does not promote the 0/229 qualification ledger or establish all-operation, cross-platform or upstream parity.

## What was actually observed

The new owner first returned an empty registry. Both cursors from the earlier owner were refused before import and again after explicitly importing the complete retained original native export. The new owner then explicitly created a snapshot, received the default 65,536-byte first page, and followed each returned `next_offset` in up to 262,144-byte requests until EOF. Every page field, per-page hash, offset, total length and full byte sequence was checked. The complete canonical bundle was re-exported unchanged; release returned zero retained snapshot count/bytes, and a subsequent read of that released cursor was refused.

The fresh snapshot's ID was `ebs1_c6517498ecbf04562c50f6a93c66e6fa9f17123df0a645d759df701b61ae8be8`, equal to the old content-derived ID for the same bytes. That equality occurred only after explicit fresh freeze; import itself did not restore a cursor. Complete opaque tool-result text and original wire frames were retained. No additional npm/original or Ghidra run occurred.

The source input was selected from the actual `native/producer` `export-full` row, gzip export and original request/response bindings after independently replaying the entire original R5 family. The new report retains those precise provenance references. An assessment digest alone was not used as the import source.

## Source and execution binding

- Source commit: `fe3223cabbd2a8f1aa75a4ab57507bdb72291242`; selected source-tree SHA-256 `1a83f83cf62bf3d96e50c944722977b6971ffe686aecd131cab5e728dd802424`.
- Runtime: 51,146,872 bytes; SHA-256 `260205be5fd4cdf363b8f426002c057d1d939ce299843f979770a585bb72faf6`.
- Final nine-stage matrix summary SHA-256: `ac9bd1e247ee2e2dc95f080f3b078ddb0d6cb2e82ed2bb4f641f18dba713c407`; all 22 original files are retained and validated.
- Producer job `1a1b2b55098-fc05-7f68` and independent consumer/owner-observation job `1a1b2b6cad0-fc05-7f71` both exited 0 with complete durable logs.
- Original report: 1,778,710 bytes; SHA-256 `12bff587014a461cd9db837d13d623689f785f1ee5474c4aa1ee6b1eabab5e08`.
- Original independent assessment: 5,210 bytes; SHA-256 `dce6f284e989243e784c692c8c410248451b60b26a4fbf8db034c0ecbe4331ce`.
- After consumer completion, the original owner identity was absent, its process group had no remaining members, and the read-only census recorded no errors or signals. The owner-close receipt recorded no forced cleanup.

The archive includes original launch/close/stdout/stderr/wire/call rows, full import bytes, full reconstruction/export gzip artifacts, source before/after plus monitoring events, the complete build bundle, exact private producer/consumer code, peer review and ten pure-data test results. Those preparation tests are separate from this actual execution. Runtime binaries, controller state and redundant mutable export files are excluded.

## Archive and actual relocated replay

The supplemental archive is `elf-native-cold-full-r1.tar.gz`, **986,591 compressed bytes**, SHA-256 `0dbb339335b795db51212655eb34d3d5b9ad0766f974f5697ffa63ef8b605618`, with **166 regular-file members / 12,665,596 uncompressed bytes**. Its `*.members.json` inventory pins every original member.

The [existing family archive](../elf-observations-r2/elf-family-r2.tar.gz) is an explicit immutable replay dependency: 6,494,352 bytes, SHA-256 `d44ce4fbc3f9c96d1468c88d0bd89eb0f6edca471ff043081e5d31ee36261020`. `source-family-dependency.json` pins it and its member manifest. Both archives were actually extracted to a fresh `/home/qian-qi/work/hepta-rea-family-ecb0b9d61c75-20261106-evidence/archive-replay-cold-full-r1` directory, with every member's byte count and SHA-256 verified. No original receipt was rewritten.

The **archived** private consumer was then executed against the relocated supplemental report and relocated original-family report, using their original report SHA pins and the matching frozen R5 checkout. It exited 0; stdout and stderr were byte-identical to the first independent consumer output. The relocated complete build bundle produced the same binding. See `commands.json`, `relocated-replay.json` and `replay-summary.json` for exact commands and artifact hashes.

Offline replay requires the matching source checkout plus these two extracted archives; it does not start the runtime, original npm server or any engine. Keep supplemental counts separate from the earlier finite family/lifecycle observations.
