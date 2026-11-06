# R34 two-file cache prune preparation

The tool is prepared and independently statically reviewed; it has not been
executed. It does not modify the sealed R34 launcher, source package, threshold
or qualification inputs. It starts no subprocess, build, test or benchmark.

Only these two rebuildable files in the closed R33 `target-build` are allowed:

| Relative path | Bytes | Device / inode |
|---|---:|---|
| `debug/deps/hepta_runtime-1b8b761b89392e3b` | 541,152,032 | 2053 / 2948723 |
| `debug/deps/libhepta_runtime-564505b54e9d81cd.rlib` | 388,308,656 | 2053 / 3173052 |

The plan must exactly equal the two-item list compiled into the script. It
also fixes each original size, modification time, link count and allocated
bytes. Both objects must pass all preflight checks before either is removed.
There is one `os.unlink` call site, supplied only by that list and a no-follow
directory descriptor. There is no directory deletion or recursive cleanup.

The test executable is anchored to original SHA256
`e2096aa99096233152ffbd11fd1d42aa145cbfa1ef9f4fa81b8191e9055ad3b1`.
The independent retained copy under `qualification-01/test-binaries/` must be
a regular, single-link file with a different device/inode pair and the same
complete SHA. The independent review confirms this SHA in the original
isolated-test audit; that auditor was not rerun.

No external SHA was supplied for the rlib. Its exact object is fixed by the
path/stat values above and in the plan. The tool computes its actual stable
full SHA before any deletion, durably records it, then hashes it again and
requires that same SHA and stat immediately before unlink. The unknown SHA
is not presented as a pre-existing measurement.

The reviewed R34 launcher is read with its frozen byte count and SHA before
loading its definitions with `__main__` disabled and assertions enabled.
Only its verification helpers are called: frozen candidate checks, complete
R33 owner closure and current source checks, retained-program hashes and the
unchanged process inspection. All cache descriptors are closed before each
process check, so the tool needs no special self-process exemption.

`cache-prune-01/` is created once. Its receipts include the full cache entry
metadata before and after, every candidate SHA/stat, independent retained-copy
identity, owner/process checks, deletion intent/result and observed free space.
Access times are excluded from metadata comparison. Other entries must remain
identical; only the selected files may disappear and their `debug/deps` parent
may have normal unlink-related size/time/allocation changes. Successful unlink
is recorded immediately so a later fsync or verification failure cannot hide a
partial deletion. Failures cause no automatic retry or additional deletion.

The original **3 GiB** requirement remains. The tool reports actual observed
free space after the operation; R34's unchanged preparer checks it again.
It makes no claim that allocated file bytes will equal newly freed space.

Install the two archive members under
`/home/qian/hepta-runtime-optimization-20261106-r34`. After the coordinating
owner's review, the one execution uses:

```json
["/usr/bin/python3","-B","-u","/home/qian/hepta-runtime-optimization-20261106-r34/cache-prune-tools-01/prune_cache.py","--plan-sha256","0e372a560b119422d41ae29c5b0d2d8c4103cbd95b7f16f3dfe75b1c47d2d256"]
```

The tool requires R34 qualification to remain unstarted. A pre-existing output
directory or qualification claim stops it; it never overwrites an earlier
attempt's receipts.
