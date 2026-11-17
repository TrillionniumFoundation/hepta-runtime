# Historical public58 and authority source profile

The default service builds the current 111-component graph with nine catalog entries and additional Batch and Bellman routes. This directory
preserves the older 58-image public fixture and the original authority profile
used by its retained component pipeline. Current authority has a separate
current-SDK comparison and evidence reader.

`source/` contains 119 exact old files: the original 112 graph/LocalRead inputs
from `f31b7645eaf9b0b41979851d46a16e1e450e1a4b`, plus seven authority files whose
bytes are unchanged in main `e7ecd543a300c33404b00a80cfb9ab4e98053cf1`.
Those seven restore the old root, profile, packer, provenance and three pin
consumers, keeping the original receipt bound to its actual source and images.

`PROFILE.json` records every size, SHA-256 and Git blob. Before creating a source
view, the materializer checks 390 current graph files and six extra authority
profile files. It restores 119 old inputs and excludes 247 current-public-only
files. The shared Batch input performance proof and its two exact authoring
inputs remain in the historical source view; the global Batch qualifier still
binds all 26 source inputs, including the five dependencies restored here. The v22 `vendor` preservation remains intact. The complete packed-worker `runtime_support` input tree is validated, copied and explicitly excluded with the other current-only files; no packed support byte is silently trusted.

```sh
python3 -I -B tests/hia_native/historical_public58/materialize.py \
  --source "$PWD" --output /absolute/path/to/new-historical-public-profile
```

All retained native pipelines, original references and readers run from that
explicit source directory. Unrelated source bytes, fixture retirement and
archive fixes are preserved. The materializer checks complete input/output
hashes and changes no input. Every old suite and deadline remains intact.

| Caller | Selected source |
| --- | --- |
| Retained public native/original pipelines | Exact old public58 graph, private fixture and complete old corpora |
| Retained authority native/original pipeline | Restored old root/profile/packer and original receipt pins |
| Current authority qualification | Current owner; 23 native groups, fresh 243 original rows and 16 integrated lifecycle rows |
| User default native build | Main root; current111 API/CLI |
| Current main qualification | 390 exact source files, nine fresh current qualification roles, actual default entry and complete public/Batch/Authority comparison |

The current workflow also retains all 1,777 complete Batch rows and 28 stdio
rows for each native and original provider. Both the frozen reference entry
and the actual installed main entry must produce the same complete executable.
The catalog remains the qualified nine-entry catalog; this change does not
claim a ten-tool or eleven-tool catalog.

The historical public reader still requires source-binding SHA-256
`0b7730769d36a4851e2d56ab717f7ce07c27d43bb728290aa7b5b32d014e82f2`.
Its oversized-input results retain the old transport profile. Current serial
framing, current identity resolution and historical authority receipts have
separate qualifications. Full SDK/136-handler, full async/cancellation,
production activation and old-runtime-removal flags remain false.
