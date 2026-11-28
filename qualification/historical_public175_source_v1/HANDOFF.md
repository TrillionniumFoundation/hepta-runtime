# Current writer source and retained qualification inputs

The public writer executable has 175 HIA image instances. Its complete 1,062
production inputs retain source binding SHA-256
`2e02569c77e019ae707719680e3d17dd05955fa3a2e2e25024bcb26b955a11ae`.
The executable remains 36,986,880 bytes with SHA-256
`773c5a8101e17ae576000260bc8687ef33f242d6bf6b9e34709c431be9b4e3ff`.
This change modifies historical qualification entry points and workflow input
selection. It does not change those production inputs.

The original public126 and public58 qualifications require their original
sources. Applying their fixed source checks directly to the newer writer graph
correctly refused the newer configuration and build inputs. Some sparse
checkouts also omitted `asm/`, although it belongs to the complete current
source binding.

`writer_projection.py` first checks every current input and the complete
261-file native inventory. It resolves all 856 retained read inputs through the
already retained original sources. In a fresh, independent directory it restores
11 exact source/binding files and four original workflow preimages, then removes
the ten writer-only native files from that historical directory. The current
checkout remains intact. File bytes, modes, the complete selected inventory,
and terminal readbacks are bound in a separate receipt.

The original `current_projection.py`, `CURRENT_PROJECTION.json`, `PROFILE.json`,
and `REFERENCE_PROFILE.json` remain byte-for-byte unchanged. They then perform
their original 162-to-126 and 126-to-58 transitions. No historical digest is
updated to accept the writer executable. The public126 workflow now names its
retained scope and runs the original frozen entry, fresh build, ELF identity
check, and independent uploaded-artifact reader on the restored public126
source. Its original limits and qualified executable pins remain unchanged.

## Actual checks

The complete 175 → 162 → 126 → 58 source chain executed successfully. Seven new
test groups exercised all 15 restore preimages, all ten native exclusions,
retained source changes, fixed authorities, uncovered source changes, additional
native inputs, symbolic links, fresh-output requirements, terminal source drift,
output bytes and modes, and forged output inventories. The nine original
current-projection tests and twelve original reference-custody tests all passed.
The unmodified frozen public126 `entry.py prepare` also accepted the complete
restored source. The fresh public126 executable build is a separate CI step;
this local source qualification does not claim to have run it.

`complete-evidence.tar.xz` contains all three complete source receipts, test
streams, original frozen-entry preparation, and the initial test-fixture failure
before the missing fixture input was corrected. Every archive member was read
back and compared with its original bytes before the reproducible temporary
source copies were removed. Production source and executable qualification
remain under `qualification/public_binary_write/v1/`.

Reproduce the current source controls with:

```sh
python3 -I -B tests/hia_native/test_historical_writer_projection.py -v
python3 -I -B tests/hia_native/historical_public58/materialize.py \
  --source "$PWD" --output /tmp/hia-historical-public58
python3 -I -B /tmp/hia-historical-public58.writer-read/tests/hia_native/test_historical_current_projection.py -v
python3 -I -B /tmp/hia-historical-public58.current-profile/tests/hia_native/test_historical_public_source_custody.py -v
python3 -I -S -B qualification/public124_default_entry_v1/source/entry.py prepare \
  --source /tmp/hia-historical-public58.current-profile \
  --capture /tmp/hia-retained126-capture
```

This is source custody qualification. It does not establish complete runtime
replacement, production activation, or permission to remove the old stack.
