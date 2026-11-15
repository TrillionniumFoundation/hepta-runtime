# Original blocking directory-creation reference

This private test transport calls the linked Rust 1.95.0
`std::fs::create_dir_all` directly. It uses the production edition and release
profile, an explicit compiler and linker, and a fresh executable process for
every compared filesystem case.

The source manifest pins the original runtime call, Cargo files, and complete
Tokio 1.53.1 bridge. Tokio delegates this blocking operation to the Rust standard
library through its worker executor. This fixture qualifies the blocking leaf;
it does not execute Tokio or qualify cancellation, executor scheduling, capture
preparation, a shared atomic statx cache, or registry publication.

## Transport

The single stdin frame is the native 64-byte HSHMKQ01 START header followed by
the complete raw Unix path. The action is 1, the initial statx-cache observation
is 0, the u64 path extent is exact, and all reserved words are zero. The process
accepts no arguments and performs no preliminary Rust filesystem metadata call.
Its parent establishes the owned working directory, inherited UID, and umask.

Two exact stderr markers, HSHMKRUST-BEGIN and HSHMKRUST-END, each terminated by a
newline, bound the actual standard-library call in the retained syscall trace.
They make no claim about private standard-library state. All trace bytes and
complete process streams are retained. Actual mkdir/statx/fallback effects and
their original raw paths and errors are compared with the native execution.

Stdout is exactly 24 bytes: HSHMKO01, a little-endian u64 kind, and a little-endian
u64 raw OS error. Kind 0 is success with value zero; kind 1 carries the original
positive raw OS error; kind 2 is the local InvalidInput result for a raw path
containing NUL, with value zero. No private cache word is synthesized.

The fixture has zero copied original unit tests. Semantic cases come from the
shared owned-filesystem specifications and actual independent native/reference
executions. Seeded Present/Unavailable native cases have no fabricated fresh
Rust counterpart. Full runtime replacement and old-stack removal remain false.
