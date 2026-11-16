# Historical public58 test source profile

The default service builds the current 83-image, nine-tool graph. This directory
preserves the older 58-image public fixture, its ordinary and wide corpora, and
its original source identity. Nothing here activates a public service or grants
current SDK qualification.

`source/` contains 112 exact Git blobs from main snapshot
`f31b7645eaf9b0b41979851d46a16e1e450e1a4b`. These are all 110 files of the original
public source closure, its binding manifest, and the original LocalRead source.
`PROFILE.json` gives every file's size, SHA-256 and Git blob, the current 172-file
graph identity, and the 47 paths exclusive to that new public graph.

To run retained qualification, create a new source directory:

```sh
python3 -I -B tests/hia_native/historical_public58/materialize.py \
  --source "$PWD" --output /absolute/path/to/new-historical-public-profile
```

All old pipeline commands, native suites and original readers then run from
that directory. The materializer copies current qualification sources, restores
the exact historical graph inputs, and excludes the exact new public-only
paths. It checks complete input and output hashes and changes no original file.
Other current fixes, including fixture retirement and archive code, remain in
the view. The receipt records this projection and never calls it a clean Git
checkout or an 83-image proof. Every old suite and timeout remains intact.

The CI workflows explicitly select this source directory in every prepare,
native, original and collection job. The old builder import therefore resolves
to the same exact file as its old source/capture/readback root. Historical
readers continue requiring 58 members and the original source-binding hash
`0b7730769d36a4851e2d56ab717f7ce07c27d43bb728290aa7b5b32d014e82f2`.

## Audited caller boundaries

| Caller | Source selected for retained execution |
| --- | --- |
| `qualify_hia_runtime_native.py`: `runtime_mcp` and `filesystem_public` builds | Materialized root; exact old 58 builder and actual private observer |
| `test_runtime_mcp.py` and public literal/regex-search suites | Same root and its 58-member metadata |
| `hia_native_runtime_mcp_evidence.py` and `hia_native_filesystem_public_build.py` | Same source binding, compiler/member files and complete wire captures |
| Runtime MCP original/reference and RawValue evidence stages | Same retained source root and unchanged case/timeout domain |
| User `scripts/hia_native_runtime_mcp_build.py` | Current main root; actual83 default API/CLI |
| Current public qualification job | Exact current172 source check, fresh 83 references, then actual main default-entry build |

The current target's serial input limit is 16 MiB including newline. Historical
wide-input successes retain their old transport profile. The current full SDK,
all 136 handlers, full async/cancellation, production activation and old-stack
removal flags remain false.
