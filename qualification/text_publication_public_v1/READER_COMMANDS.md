# Exact build and read entry points

Copyright 2026 Muvon Un Limited. SPDX-License-Identifier: Apache-2.0.

All variables below identify separate immutable checkouts or fresh output directories. Build HIA/Rust only in CI or the authorized remote environment. Evidence readers execute no HIA/Rust.

## Actual default build

Use production source commit `10ed63b232e54213522273997f25f1304ee87cdd` and Hepta `d3e2c90173cf733e42b299d0c4274df4b593a12f`. This exact default entry already passed CI `44057425960`; no repeat is necessary for receipt review.

```sh
python3 -I -S -B "$SOURCE/scripts/hia_native_runtime_mcp_build.py" \
  --source "$SOURCE" --hepta "$HEPTA" --output "$FRESH_OUTPUT"
```

The frozen qualification wrapper/reader/workflow are at commit `a5f185f3b7ef6bb22a28ea611db918016a74434b`, `qualification/text_publication_public_default_v1/source` and `.github/workflows/hia-text-publication-public-default-v1.yml`. Both jobs retain 15 minutes; pure read operations retain 180 seconds. The original default build uses fresh 115+8 compiles, no reused leaves.

## Full public uploaded-evidence read

Use the recovery reader source at `24ae71cb3c017269d3c82d44b4ba5476fee17045:tests/hia_native/text_publication_public_recovery_ci/source` and the final read program at `0030068a812a9c2161ea3f3be0a0cc7e6b3d99ef:qualification/text_publication_public_final_read_v1`. The program reads all 25 fixed recovery artifacts plus complete original graph/reference archives. Authentication is the standard `GH_TOKEN` environment variable; do not include it in logs.

```sh
python3 -I -S -B "$FINAL/read_final.py" \
  --reader-source "$RECOVERY" --work "$FRESH_WORK" --output "$FRESH_PROOF"
```

Uploaded proof artifact `14316085590` includes `READONLY.json`, `RESULT.json`, complete per-artifact FILES/ARCHIVE indices, frozen reader source and both parent indices. Its complete ZIP is 5,339,105 bytes, SHA-256 `6bef2f873773dc62bbaf333ac398b71af8019df6949c64bdaebfccf27951fedb`.

## Full actual-default uploaded-evidence read

Use the frozen default qualification source above. This exact read already passed job `133951525508`:

```sh
python3 -I -S -B "$DEFAULT/read_uploaded.py" \
  --run 44057425960 \
  --artifact-name public123-default-entry-a5f185f3b7ef6bb22a28ea611db918016a74434b-1 \
  --work "$FRESH_WORK" --output "$FRESH_PROOF"
```

The original build ZIP is artifact `14316332302`, 94,233,997 bytes, SHA-256 `d5ea0e00650146d7248ad88c6dde1f20bee9c727043929018dd2c6742cf0c64b`. The independent small proof is artifact `14315848778`, 984,352 bytes, SHA-256 `9ac3c09de3c3214d4e73b9884ee8f0c1deef2508b23f369fe4f1a8d9c69ea526`.

Every read verifies complete member sets, byte hashes, modes, source/ELF identities and immutable before/after evidence. The full semantic execution and old failures are retained; readers do not synthesize expected responses.
