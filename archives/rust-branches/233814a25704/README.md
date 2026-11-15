# Preserved Rust branch variant

Original branch: `fix/rea-request-audit-private-root-20261103`. Original commit: `233814a257044a5a42683d3dc6388b0906986858`.

Superseded by prepare_controller_state_dir with private recursive creation, exact 0700 mode and current UID checks, plus permissive-umask subprocess regressions. Preserve the older implementation and test without weakening the later owner validation or private startup receipt.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.
