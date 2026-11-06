# macOS create-only preview publication

The macOS branch of `src/mcp/rea_store.rs::install_staged_exclusive` was
extracted verbatim after formatting and compiled on the configured Mac in an
isolated temporary Cargo project. The exact function SHA-256 is
`a76ef2d9a5e92e54885080d7de7a1b05240b979f5c92c631fcbd38d8c2ce0aa1`.
The source file at extraction had SHA-256 `e0d4c406cb3ec603b7bb9653033c8ba74fe89e2dd3e6a3176d432ae97ab78031`.

The probe used Rust 1.95.0 on arm64 macOS 26.6.2 (Darwin 25.6.0).
Its anyhow 1.0.104 and libc 0.2.189 versions and registry checksums were copied
from this runtime's Cargo.lock. It called the real libc `renamex_np` binding
with `RENAME_EXCL=4`; no syscall stub was used. Cargo and the probe exited 0.
Original compiler output, probe output, source bytes and hashes are retained
beside this document. `ARTIFACTS.json` maps original probe filenames to the
retained text artifacts.

## Observed checks

| Check | Observation |
| --- | --- |
| First create-only publish | Staging name consumed, committed inode has one link and mode 0600 |
| File and parent-directory synchronization | Staged file sync and directory sync returned success on the tested filesystem |
| Existing destination | Existing bytes unchanged, losing staged bytes retained |
| Existing destination symlink | Symlink and target preserved; no overwrite/follow-through |
| Missing source | Error and no destination creation |
| Concurrent publishers | Eight rounds of eight simultaneous publishers had exactly one winner per round |
| Immediate process exit | A child exited immediately after the helper; the committed inode remained readable with one link |

The helper and same-operation tests cover atomic name publication and
create-only collisions on the tested Mac filesystem. They do not establish
full macOS MCP qualification, all filesystem support, external-volume
behavior, hardware power-loss durability or Hepta model-session adoption.
A successful `fsync` is recorded as a syscall result, not a power-cut test.

## API sources

Apple's official XNU [rename manual](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/rename.2)
specifies that `RENAME_EXCL` returns `EEXIST` for an existing destination on
supporting filesystems. The [Darwin declaration](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/stdio.h)
and [wrapper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/renamex.c)
provide the actual three-argument function.
The [Rust libc Apple module](https://github.com/rust-lang/libc/blob/c6eecb745d4011f4b0ae9fd9a5b7d4408c2c5e28/src/unix/bsd/apple/mod.rs)
exports the corresponding signature and flag. The executed pinned dependency
is recorded in the probe Cargo.lock, independently of that source reference.

## Reproduction

Create a new temporary directory. Copy `probe-Cargo.toml.txt` and
`probe-Cargo.lock.txt` to Cargo.toml and Cargo.lock; copy `probe-main.rs.txt`
and `publish-helper.rs.txt` to src/main.rs and src/publish_helper.rs.
Run `cargo run --locked -- /absolute/absent/test-files` on macOS with Rust
1.95.0. The target test-files directory must be absent. The harness only writes
inside that directory and does not operate any service.
