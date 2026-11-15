# Original shell and background test oracle

This crate is test infrastructure. It compiles the complete original shell and
background owners, the complete request context, and all 21 original owner
tests. It is not part of the HIA runtime implementation or a production routing
claim.

## Reproducible source and dependency boundary

The reference script materializes original source bytes from the fixed source
manifest. The shell, background, request context, and original test bodies are
unchanged. The complete original background file is retained as a byte prefix;
an appended, separately identified child module exposes test-only access.

The source manifest binds the original Git commit, tree and blobs, whole-file
SHA256 digests, and every half-open extraction span. The original call type,
remote path parsing, truncation helpers and ViewCache type declaration are
included from their exact spans. No ViewCache methods are compiled or qualified.

Every selected registry package uses the original lock's name, version, source,
checksum and complete dependency identities. Cargo's short or version-qualified
dependency spelling is normalized only by resolving to the complete package
identity in that lock. No version, source, checksum or edge is substituted.
Explicit features reproduce the actual production metadata feature union,
including already-present transitive dependencies. The driver reruns locked
metadata on the original production inputs to verify that union.

Each fresh qualification stores the original and derived locks, all original
source files, the exact materialized crate, production metadata input files,
complete metadata stdout, all original crate archives, per-file source digests,
actual Rust tool and oracle executable identities, and every process's separate
stdout, stderr, deadline, exit code and receipt. Actual cache source bytes are
checked against each original lock checksum before and after the build.

## Build and original tests

Run the repository script with explicit Linux x86_64 Rust 1.95.0 tools:

    python3 -I -B scripts/hia_native_shell_process_reference.py \
      --runtime RUNTIME --output FRESH_BUILD \
      --rustc ABSOLUTE_RUSTC --cargo ABSOLUTE_CARGO

Use --offline only when every required crate is already available. The build and
all 17 original shell tests plus 4 original background tests use --locked. No
original test is ignored or substituted.

The Python API read_evidence(runtime, output, rustc=None, cargo=None) is a pure
reader: it never starts a process, builds code, loads a native module, or reads
live /proc. It validates the complete source, dependency, process and executable
evidence against current real files. It does not support path relocation or
missing-tool assumptions.

## Real-process fixture

The executable's --fixture mode takes JSON lines on stdin and produces JSON
events on stdout. The first request is:

    {"op":"execute","command_hex":"...","cwd_hex":"...",
     "timeout_ms":10000,"capture_dir":"/absolute/empty/directory"}

A UTF-8 command field can replace command_hex. Working directories retain raw
Unix bytes through cwd_hex. The controller supplies the same controlled
environment, command, working directory, deadline and ready-file gate to the
original and native implementations.

The fixture calls the original private execute_with_timeout function. It does
not replace preparation, spawn, wait, promotion, cancellation or shutdown.
A read-only observer opens the original log files before the ready gate is
released, preserving foreground raw bytes after the original discard unlinks
those files. Captures are stdout.bin and stderr.bin under capture_dir.

Every event has schema hepta.runtime.shell-process-fixture-event.v1, event,
seq, oracle_pid, elapsed_ns and unix_ns. Events include started, capture_ready,
foreground, promoted, completion, cancelled, shutdown and final. PID, timing,
raw captures, original outcome text, hints and original callback observations are
retained. Raw wait status is not exposed by the original API and is explicitly
marked unobservable instead of inferred.

The controller must keep stdin open while observing completion. Natural final
completion exits even if stdin remains open. EOF is explicit shutdown.
{"op":"cancel"} aborts only the foreground caller; after promotion it does not
abort the background waiter. {"op":"shutdown"} calls the original kill-all path.
The fixture does not silently clean up a foreground-cancelled original tracker.
Original stale-PID behavior and native custody protections remain a separate,
explicitly bounded comparison domain.

## Background rendering fixture

--background-render takes a sequence of little-endian u64 lengths followed by
HSHBGT01 request frames from native/shell_background_text_abi.md. It emits a
little-endian u64 return, u64 extent, and the complete HSHBGR01 response.

Operation 1 creates stable full log files and calls the unchanged original
read and resource_text functions. Operation 2 projects already-observed
read_tail bytes and flags through byte-exact original read-combination and
resource-format statement spans. Its input is not an emulation of filesystem
I/O. Operations 3 and 4 call the original URI and URI-parser functions.
Arbitrary valid UTF-8 IDs are carrier values and are never used as filenames.

The semantic replay consumes the complete deterministic 3456-case native
requests.bin and responses.bin. The separate 51 native transport controls are
not counted as original Rust semantic cases.

    python3 -I -B scripts/hia_native_shell_process_reference.py \
      --runtime RUNTIME --output FRESH_REPLAY \
      --rustc ABSOLUTE_RUSTC --cargo ABSOLUTE_CARGO \
      --reference-build FRESH_BUILD --background-corpus NATIVE_CORPUS

This reuses only the fully verified fresh reference build. It retains original
binary stdin, native responses, complete original stdout and stderr, and a
single actual replay-process receipt. Every original/native response byte is
compared. read_background_evidence(runtime, build_output, native_corpus, output,
rustc=None, cargo=None) independently rereads that evidence without execution.

Passing these tests qualifies these observed and pure domains only. It does not
qualify a complete production Shell handler, background filesystem owner,
registry integration, whole-runtime replacement, or old-stack removal.
