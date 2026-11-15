# Preserved Rust branch variant

Original branch: `fix/runtime-sftp-runtime-mode-quarantine-20261023`. Original commit: `faf2a12373788560979f525b40a0588f1620b1e9`.

Current runtime remote effects use the descriptor-relative file owner; raw runtime-mode SFTP remains restricted. Preserve the old blanket quarantine patch without removing the later guarded supported route; root-ancestor trust remains an explicitly documented limit.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.
