# R34 first qualification preparation

This is a sealed input package for the first R34 qualification. The preparer has
not been executed. No Rust build, test, benchmark, original auditor or remote
operation was run while producing this package. It is not a qualification or
performance result.

## Source and cache ownership

The accepted source baseline is R24 commit
`baab4def80be7af015b2e7a594cb302f66c4130e`. The complete frozen R34 candidate
package remains under `candidate/`, retaining its original 22 files and Git
catalog `04968ea30cb3b08d4790d8b3f18fc62f69e3dab8`. The original four changed
paths, 220 compiler inputs, eight new test functions and patch are unchanged.

The new working source is created only from the accepted R24 source tree and
`candidate/candidate.patch`. R33 supplies only its closed `target-build`
directory. That directory is renamed, not deleted or copied. R33's source,
reports and separately retained qualification executables remain in their
original locations.

R33's qualification and exact CI passed. Its observation workflow completed,
but the original C8 performance gate failed. The original normal lifecycle
materializer therefore failed at its guard before a lifecycle run. Neither
cache reuse nor this seal adopts R33 performance.

## Changes from the successful R33 preparer

The reference preparer is Git blob
`8f535b96eeb2c61e3ef8774c7217711239f0f165`, 25,125 bytes, SHA256
`c1e6ef1bf6d4a1c42a644a220ab00a5b14b95281e76e24f94526d367a07f351d`.

- The destination and cache-owner paths now identify R34 and R33 respectively.
- The R33 two-profile source chain is replaced by the immutable R34 candidate
  manifest/input and four-path patch. The accepted baseline remains R24.
- The owner gate binds twelve actual R33 receipts plus the original postflight
  receipt. It preserves successful execution and rejected performance as
  separate facts. The holder's actual two JSON records and the lifecycle
  materializer's actual empty stdout are handled explicitly.
- Twelve general helpers remain byte-identical, including the stable bounded
  reader, process inspection and its exact existing opaque-helper exceptions,
  retained-program checks, native-terminal checks and qualification checks.
- The original 19 qualification harness files, `--jobs 2`, all eight stages,
  retry policy, thresholds, atomic first-attempt claim and 3 GiB free-space
  check remain unchanged.

The owner CI count tuple, 1649 passed / 0 failed / 34 ignored / 1683 selected /
0 retries, belongs to R33. It does not predict the result or inventory of R34.

## Sealing evidence and limits

The local sealer read and hash-checked eleven complete owner originals. The
3,563,463-byte observation report was not downloaded for this preparation.
Its SHA256 `29d78532dd7d6cfd7ea8f044f410e3dae419d9eb87691adfa277347ff91d7529`
agrees between the original parent report and the original postflight. The
remote preparer must read, hash and validate that original report before
moving the cache. No archived program is executed by the sealer.

The actual lifecycle job is `1a1aed5c50a-fc05-6301`: failed, exit 1, stdout
0 bytes, stderr 741 bytes, with the original observation-gate error. Its
native/read byte custody and the three absent normal-lifecycle output paths
are retained. The original holder is `1a1aecd302a-fc05-6294`, succeeded with
exit 0 and its owned agent reaped.

The input archive contains 30 regular files, totaling 1,025,362 uncompressed
bytes. Every packed member was checked against the exact payload bytes.
`frozen-preparation-manifest.json` lists the other 29 files and is explicitly
self-excluded. The installation layout has five top-level files, 22 files in
`candidate/`, two in `preparation-tools/` and one postflight provenance file.
It contains no runtime `source/`, `target-build/` or `qualification-01/`.

## Runtime order

1. Verify the fixed script/root/user and absent first-attempt output paths;
   atomically claim `preparation.json` so a duplicate cannot replace it.
2. Verify hash-bound launch inputs, self identity and every frozen candidate
   member. Verify the accepted R24 report, current 220-input map and 19 harness
   identities; require exactly the four selected changed paths.
3. Read and check all actual R33 owner receipts, current qualified source map,
   complete native terminals/read streams, seven observation stages, all
   observation round shutdowns, the C8 rejection and lifecycle guard.
4. Require a canonical old cache, the original 3 GiB free-space minimum,
   preserved executable hashes and no old-cache process owner or compiler.
5. Rename the cache once, verify the same device/inode, then recheck retained
   executables and every bound owner receipt.
6. Copy R24 source, check its map/harness, apply the exact frozen R34 patch and
   verify all 220 resulting input hashes. Invoke the original qualifier once.
7. Preserve the real return code and final maps/report, including any failure.

The existing free-space gate is evaluated against current runtime state. A
sealed package does not assert that the machine is idle or that sufficient
disk space is currently available.

## Single qualification entry point

Install the archive's relative paths under
`/home/qian/hepta-runtime-optimization-20261106-r34`. The first native launch,
after the coordinating owner's review, uses exactly this argument vector:

```json
["/usr/bin/python3","-B","-u","/home/qian/hepta-runtime-optimization-20261106-r34/prepare_qualify.py","--input-sha256","7065ad29178dbec61a1ed78fa24c9697cd6b6d3fed1ca9d5bb6cb7335b097e1e","--owner-closure-sha256","94b2649e0a8b66711b122638432848a41af37f06a10973f81e7be21d5705ebb9"]
```

The local `seal_preparation.py` has already created `sealed-01` once and refuses
to overwrite it. The earlier `*.template.json` files remain unsealed historical
drafts and are not part of this installation archive.
