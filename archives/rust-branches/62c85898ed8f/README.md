# Preserved Rust branch variant

Original branch: `fix/http-mcp-security-standalone-base-20261022`. Original commit: `62c85898ed8fbcd9d9b9776bcc5f55aad9a48f76`.

Actual standalone-HTTP auth gap is reconciled in current main.rs/cli.rs by universal token and loopback validation plus eight regressions. Archive the old whole-file patch so current credential scopes and unrelated startup paths remain intact.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.
