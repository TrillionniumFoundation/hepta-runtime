# Preserved Rust branch variant

Original branch: `fix/rea-preview-linux-atomic-publish-20261103-gpt6`. Original commit: `d875438db6d20f2c0218fde7a47f79a42d66b088`.

Linux RENAME_NOREPLACE publication is already present in current rea_store.rs, with later macOS exclusive-rename and durability handling. Preserve original source/tests without regressing those platform and owner safeguards.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.
