# Capture-path original Rust projection

This separate, std-only test executable leaves the complete shell/background
oracle and its 21 original tests unchanged.

The manifest pins original source spans and every primitive-observation edit.
`Path` equality and `Path.parent` execute the linked Rust standard library.
The original `jobs_dir`, `next_id` and stdout/stderr join statements are
materialized from their exact source spans. Only TMPDIR/PID observations are
replaced by typed input. Linux's TMPDIR fallback is selected explicitly from
the pinned standard-library function. The original
`AtomicU64::fetch_add(1, Ordering::Relaxed)` executes after fixture counter seeding.

Requests use HSHCPQ01 plus seven little-endian u64 words and raw byte fields.
Responses use HSHCPR01, a fixed 80-byte header and a full u64 body extent.
Stream requests carry a u64 length; responses carry return 80 and full length.
The native ABI defines the wire. NUL TMPDIR cases are typed projections, not
actual environment variables. Python does not calculate expected path results.

Builds use explicit Rust 1.95.0 GNU Linux tools, the production edition and
release profile, a fresh directory, explicit sysroot/linker and isolated
environment. Complete source, streams, process receipts, toolchain identities
and executable bytes are retained for a read-only evidence reader.

This fixture does not execute production prepare, real TMPDIR lookup or PID
acquisition, filesystem creation, registry locking, concurrent counter updates,
promotion, callbacks or MCP dispatch. It covers the registered typed projection
and standard-library path operations only.

Runtime snippets retain their Apache-2.0 provenance. The Rust temp_dir snippet
is from rust-lang/rust 1.95.0, under Apache-2.0 or MIT; its upstream URL, Git blob,
full-file hash and span hash are recorded in source_manifest.json.
