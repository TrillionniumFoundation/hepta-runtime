# Reproducing the operation-record fixtures

The existing `run_operation_projection_abba.py` is the complete source generator.
Its `--prepare-only` entry returns before binary selection or benchmark execution.
No compressed or uncompressed fixture payload is required in Git.

From the directory containing that script, use a new absolute destination whose
parent already exists:

```sh
umask 077
python3 run_operation_projection_abba.py --fixtures /absolute/path/new-fixtures --prepare-only
```

The generator refuses an existing destination, creates the root and its `plain`
and `escaped` subdirectories with mode `0700`, and creates each receipt and the
manifest as a new single-link file with mode `0600`, owned by the invoking user.
This creation procedure restores the required permissions after a Git checkout;
Git's source-file modes are not fixture permission metadata.

Both receipts use the filename `operation-projection.json` and contain exactly
4,194,272 encoded bytes. The plain argument has 4,193,740 decoded bytes. The
escaped argument has 2,096,870 decoded bytes, consisting of newline characters
encoded as JSON escapes. The fixture target is `never-connect.invalid`; preparation
only writes local fixture files.

| Payload | SHA256 |
| --- | --- |
| plain | `63b77ac5614a031560b65c06b13e06e31d6b9aebcf1f281ff861bb8d18b799e8` |
| escaped | `6448e0a47b79575a013f838f9ab51986c68007bb301486e764e250f88a51e780` |

Use the newly generated `manifest.json` with those newly generated files. Its
device, inode, UID and timestamps intentionally describe the local files and
will differ from the original X230 manifest. Reusing the original identity
manifest, copying receipts over it, or changing permissions after preparation
would invalidate the driver's before/after identity checks. The payload bytes,
lengths and SHA256 values above are reproducible.

`fixture-reproduction-check.json` records a completed byte-for-byte regeneration
check against both original X230 receipts, including modes and ownership.
That check ran only the preparation function, removed its temporary output,
and preserved the original fixtures and manifest. It is not benchmark evidence.
