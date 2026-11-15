# Preserved Rust branch variant

Original branch: `fix/runtime-ssh-bounded-duplex-20261022`. Original commit: `103cae318756e780492c2c22980e07b244740f06`.

Current ssh_direct owner retains bounded stream capture, duplex IO and caller-cancellation cleanup. Preserve the old bounded SSH implementation/tests without replacing later original-child custody and direct transport.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.
