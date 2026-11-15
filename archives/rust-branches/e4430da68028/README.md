# Preserved Rust branch variant

Original branch: `fix/runtime-remote-receipt-fsync-20261023`. Original commit: `e4430da68028d6e300682be7923926b98c0728db`.

Current private_read_json and bound_remote_code strengthen corrupt/symlinked status/cancel receipt refusal with nofollow/nonblock, owner/link/size/stamp validation and pinned directories. Existing stage_file, request, owner and terminal publication retain the original fsync ordering. Preserve earlier receipt implementation/tests without reverting later owners.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.
