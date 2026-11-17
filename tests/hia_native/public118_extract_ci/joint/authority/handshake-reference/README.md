# Actual current get_info handshake reference

This isolated source package has not executed Rust at its source freeze. It extracts the complete get_info method, claude/channel constant and two existing protocol feature functions byte for byte from the exact d3d75 server source. The full original file, extraction spans, required import origin, target lock and SDK source checksums are retained. The extracted method calls the actual RMCP builders and Implementation::from_build_env; observed result wire is never embedded as an implementation.

The new observer is an explicit revision of the retained G2 observer. Both original G2 files are included for review and are not compiled. The new Rust file has the complete 2026 Muvon Apache header. The unchanged cache seed has exact original Git blobs in SOURCE_INPUTS.json and is never built or executed.

The observer calls Recorder.serve on an owned Tokio duplex stream. Actual RMCP 3.9 code performs initialization, negotiation, peer-info update, metadata extraction, validation, dispatch and wire serialization. Each request is delegated to the real ServerHandler implementation. The observer retains actual running.peer().peer_info after serve completes, every request context before dispatch, and the peer state after dispatch.

## Domain

The 54 sessions cross nine versions with six ID forms. Versions include four legacy revisions, 2026-07-28, an unknown future version, an empty string, Unicode and a JSON string containing NUL. IDs cover positive and negative integers, an integral float spelling, escaped text, Unicode and 4 KiB ordinary text.

Every session sends initialize, ping before initialized, the initialized notification, ping with complete legacy metadata, ping without metadata, ping with complete modern metadata, and a final ping without metadata. All six responses are retained as whole wire: 324 total. The modern metadata ping's actual method_not_found response is retained and required, giving 54 error responses. No request is omitted to make a public comparison pass.

The sequence checks temporary request metadata overrides and the unchanged negotiated peer state. The next request without metadata must resolve through that state. It invokes no tools, file operations, external target or cancellation workflow.

## Embed in CI

```sh
python3 -I -B <source>/scripts/run_reference.py \
  --source <source> --rust-bin <rust-1.95-bin> --output <new-reference-output>
```

This entry requires CI=true. It derives the fixture lock from the original target lock, verifies all retained crate checksums and source bytes, builds in a fresh target directory, and runs 54 processes with individual 60-second deadlines. Fetch/build steps retain 180-second deadlines. Actual duplex response and close deadlines remain three seconds. Keep the surrounding 15-minute CI job gate.

Retain the complete output except the rebuildable rust-build directory. Evidence includes exact inputs, raw stdout/stderr, process receipts, the original generated module and extraction receipt, fixture lock, registry archives, source verification and the actual reference-bin executable.

The public runner may import scripts/cases.py. Native input for one case is its ordered event wire strings with LF appended. Expected output is the same original observation's ordered response_raw strings. The initialized notification has no response. Compare complete wire, retaining all modern metadata errors. Any public mismatch remains an integration failure for that domain.

```sh
python3 -I -B <source>/scripts/verify_reference.py \
  --source <source> --run <reference-output> --require-pass
```

The independent reader checks real negotiated peer state and effective request contexts in addition to wire. It audits mutations and child execution and checks source/evidence bytes, mtime and ctime before and after reading. It prints its result and does not write into evidence or execute either implementation.

Full SDK, arbitrary supported-version configurations, all 136 tools, full public protocol, asynchronous task/cancellation semantics, production activation and old-path removal remain false. This reference is for current get_info and ordinary negotiated context, not complete non-CallTool replacement.
