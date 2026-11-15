# Independent source-mask review

The first execution-input fix rejected storage under the fixed input roots but
missed the selection's additional workspace members. `extra/Cargo.toml`,
`extra/src/lib.rs` and `generated/build.rs` entered the normal snapshot, yet a
target/output mask at their parent directory hid them. The independent reviewer
reproduced this gap before the unified matrix was started.

The guard now checks actual selected files with storage masks disabled, after
the inexpensive fixed-root and outside-repository checks. The same nine-test
suite runs against the exact earlier producer and the corrected producer:
the earlier producer fails all three extra-member subcases; the corrected
producer passes all nine tests. Exact source/test/output digests and process
exit codes are preserved in `red.json` and `green.json`. These tests observe
real temporary files and Linux inotify, not simulated engine qualification.
