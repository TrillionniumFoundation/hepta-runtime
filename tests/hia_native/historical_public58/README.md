# Historical public58 and authority source profile

The default service builds the current 91-image, nine-tool graph. This directory
preserves the older 58-image public fixture and the original authority profile
used by its retained component pipeline. Current authority has a separate
current-SDK comparison and evidence reader.

`source/` contains 119 exact old files: the original 112 graph/LocalRead inputs
from `f31b7645eaf9b0b41979851d46a16e1e450e1a4b`, plus seven authority files whose
bytes are unchanged in main `e7ecd543a300c33404b00a80cfb9ab4e98053cf1`.
Those seven restore the old root, profile, packer, provenance and three pin
consumers, keeping the original receipt bound to its actual source and images.

`PROFILE.json` records every size, SHA-256 and Git blob. Before creating a source
view, the materializer checks 191 current graph files and six extra authority
profile files. It restores 119 old inputs and excludes 58 current-public-only
files. The v22 `vendor` preservation remains intact.

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
| User default native build | Main root; current91 API/CLI |
| Current main qualification | 197 installed files, fresh91, actual main entry and whole-executable comparison |

The historical public reader still requires source-binding SHA-256
`0b7730769d36a4851e2d56ab717f7ce07c27d43bb728290aa7b5b32d014e82f2`.
Its oversized-input results retain the old transport profile. Current serial
framing, current identity resolution and historical authority receipts have
separate qualifications. Full SDK/136-handler, full async/cancellation,
production activation and old-runtime-removal flags remain false.
