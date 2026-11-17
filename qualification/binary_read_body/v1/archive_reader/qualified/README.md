# Native binary read, fingerprint and private-read qualification

The immutable input domain is 114 actual files or path failures in 15 groups:
81 bounded binary reads, 17 full streaming fingerprints and 16 private reads.
The exact current target binary_file.py and file_metadata.py execute on the
same actual fixtures as the HIA-owned native syscall callable. A selected 15
cases also execute with the native observer disabled. Two contexts exercise
30 explicit admission, borrowed-response, release, destruction and EOF controls.

The already qualified build is reused byte for byte. No native build, Rust
build or application execution occurs in the pure readers. Every owned HIA
input, whole workspace before/after, whole output before/after, child buffer,
kernel request/resume, transport stream and observed process arena is retained.
The observer writes to a bounded pipe drained into lossless gzip during capture;
an expanded ordinary journal is never created or deleted. Shared buffer storage
retains every full logical byte through exact content-addressed blocks.

Real fixture snapshots include complete regular bytes, directory and special
file kinds, symlink targets, mode, ownership, device, inode, link count, size,
mtime and ctime. Atime is intentionally excluded because observing file bytes
can advance it. Fixtures are descriptor-relative, including paths longer than
4096 bytes. Their encoded snapshots survive the ephemeral CI runner.

The paired comparison covers structured exceptions (type, errno, filename,
and literal business message), as well as complete successful JSON values.
Original human-readable operating-system diagnostics are retained separately.
The outer public stderr formatter, mutating races, metadata inspection,
publication/write/upload, SSH, actual async cancellation and public routes
remain separate obligations. No full runtime replacement or old-stack deletion
is asserted by this private component qualification.

Six complete physical corruptions and two complete relocated copies exercise
the same pure reader. The whole archive binds every ordinary file, directory,
mode and byte. Failures, cancellations and unknown executions remain distinct;
an incomplete semantic process is not silently rerun.
