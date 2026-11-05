# Source inputs and Cargo artifact identity

The first combined qualification attempt at source commit
`0e4456a467614bb65e89f865a5df62e1f88963ab` stopped before executing any
build or test stage. Its `observe_binary` path reused the source-input
single-link restriction. Cargo's normal `debug/hepta-runtime` and
`debug/deps/hepta_runtime-<hash>` output aliases therefore caused an invalid
qualification. That original failed receipt is retained separately; no build
or test PASS is attributed to it.

Source inputs still require a single-link regular file. Their acquisition
uses `O_NOFOLLOW | O_NONBLOCK` and compares device, inode, mode, link count,
size, mtime and ctime before and after hashing and against the final path.
This restriction prevents an unmonitored hardlink alias from hiding a source
write followed by restoration.

Generated Cargo artifacts use a separate observation entry point. Multiple
hardlinks are allowed in the task-exclusive target, while all of the regular
file, no-follow, nonblocking and FD/path stability checks remain in force.
This is a bounded output observation after Cargo exits, not evidence that
other aliases cannot ever be written. The final Runtime is copied into a
separate immutable-mode file and hashed against the explicit build artifact
before operational qualification.

Actual filesystem regressions cover Cargo-style output hardlinks while
source aliases remain rejected, existing and dangling symlinks, directories,
missing outputs, and nonblocking FIFO rejection. The prior source monitoring
and write-and-restore regressions remain unchanged. A fresh combined matrix
is required after this correction; its success does not qualify all upstream
operations or production replacement.
