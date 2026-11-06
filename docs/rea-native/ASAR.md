# Native ASAR inventory and explicit JavaScript source acquisition

The runtime can inspect an Electron ASAR without Node, extract no files, and deliver bounded bytes from one explicitly selected packed member. The JavaScript graph tool can acquire those members directly into its existing Rust Oxc worker. JavaScript, package scripts, Electron applications and archive links are never executed.

This implements a bounded native acquisition profile. It is not the complete upstream `analyze_javascript_application` contract, a retained REA analysis view, or a REA `ev_` identity. The complete upstream compatibility ledger remains the authority for migration qualification.

## Agent workflow

1. Call `rea_inspect_asar` with the absolute archive `path` inside a configured controller workspace. Its sorted inventory includes packed files, directories, link declarations and unpacked file declarations.
2. Keep `source.observed_version` and `source.header_sha256`. Supply both as `expected_version` and `expected_header_sha256` on every continuation or member acquisition. First-page calls may also use them as explicit preconditions.
3. Read an exact inventoried packed member with `rea_read_asar_member`, or select it in `rea_inspect_javascript_graph` with the optional `source.asar` object. No import or declaration implicitly selects another file.

Example graph request after receiving the actual archive identities:

```json
{
  "sources": [
    {
      "id": "src/main.js",
      "path": "/configured/workspace/app.asar",
      "asar": {
        "member": "src/main.js",
        "expected_version": "ASV1_TOKEN_FROM_INSPECT_ASAR",
        "expected_header_sha256": "HEADER_SHA256_FROM_INSPECT_ASAR"
      },
      "syntax": "javascript",
      "module_kind": "module"
    }
  ],
  "collection": "imports"
}
```

The placeholder strings in this example must be replaced with the returned identities. `expected_sha256` on a graph source, when supplied, refers to the **complete selected member bytes**, not the archive header or entire ASAR. Several different members can share one archive path. Repeating the same file/member selection under a different logical source ID is refused.

Without `asar`, source admission and canonical source/graph identity retain the existing ordinary-file behavior. Identical source bytes, logical IDs and explicit grammars produce the same `graph_sha256` whether acquired from ordinary files or ASAR. ASAR acquisition provenance is added as `archive_sources`; the graph digest does not purport to bind archive filesystem metadata. The per-source identity and ordinary-file response do not acquire an empty placeholder provenance field.

## Identity and integrity

| Field | What it binds |
| --- | --- |
| `source.observed_version` | Unix metadata observed on the admitted open descriptor, including inode, device, size, ownership, mode, link count, modification and change timestamps. It is not a content hash. |
| `source.header_sha256` | The size Pickle, header Pickle, exact UTF-8 JSON header bytes, and alignment padding. It covers bytes `[0, source.header_bytes)`, with `header_sha256_scope: "complete_pickle_header"`. This is not the Electron fuse digest, which covers only the JSON header string. |
| `source.header_pinned` | Whether the caller supplied and matched the required descriptor/header preconditions for this request. `header_pin_authenticated` remains `false`; matching a caller-supplied value does not establish how the caller obtained or trusted it. |
| `result.member_sha256` | All bytes of the explicitly selected packed regular member, even when only a small range is delivered. |
| `result.range_sha256` | Exactly the bytes represented by the returned `bytes_hex`. |
| `result.declared_integrity_verified` | Whether a present supported SHA256 declaration and every declared block digest matched the complete selected member. A missing declaration is `false` and `integrity_status: "not_declared"`. |

Every selected-member read first validates the whole header and all packed extents. It then streams the complete selected member through SHA-256, verifies all declared blocks when present, and retains only the requested range. A corruption outside the delivered range still refuses delivery. The controller independently compares the header, returned range and whole-member commitments against its original descriptor and checks the descriptor metadata again. Unsupported declarations or a mismatch yield an error without a partial successful payload.

The native Pickle-header digest and Electron's JSON-header fuse digest are different byte scopes and cannot be substituted for each other. The independent reference records both to verify this distinction. An externally trusted native header digest can constrain admission, but this API does not attest the origin of a supplied pin. The member declarations inside that header remain self-declared consistency data unless a separate trust decision binds them.

These checks do not authenticate the publisher: an attacker who replaces both data and its declarations can make their own values agree. An inventory does not verify unselected member payloads. No whole-archive content identity or unpacked sidecar identity is claimed. Ordinary concurrent replacement or writing is rejected; privileged races that defeat or restore the descriptor observations are outside this guarantee.

## Supported format and refusals

The qualified format is the canonical pair of 32-bit little-endian Electron Pickles: a four-byte size payload followed by a four-byte-header Pickle containing one length-prefixed JSON string and zero alignment padding. All lengths and data extents must fit the admitted regular file. The JSON parser rejects duplicate keys, including duplicate decoded names with different JSON escape spellings, invalid UTF-8 and lone surrogate strings.

The root has one `files` object. Directory, packed-file, unpacked-file and link node fields are checked against the explicit supported grammar. Sizes are nonnegative JSON integers and offsets are canonical unsigned decimal strings, each within the exact `2^53-1` range. Floats, signs, exponents and suffixes in offsets are not coerced. All nonempty packed spans must be disjoint. Empty files may share a boundary. Unreferenced data gaps are counted as `unreferenced_payload_bytes`, not promoted to named member content.

Names are exact relative POSIX components. Empty, dot, parent, slash/backslash-containing, colon-containing and control-character components are refused. Paths are never normalized to a different member. Link targets are validated as literal archive-relative paths but are not resolved; their existence, cycles and eventual target type remain unobserved. Unpacked entries and directories are never opened. An `app.asar.unpacked` sibling, an absolute header path, or a source import never authorizes another file read.

Declared integrity supports explicit `SHA256`, a lowercase 64-character digest, a positive block size, and exactly `max(1, ceil(size / blockSize))` lowercase block digests. An empty member has one empty-content block digest, matching `@electron/asar@4.2.0`. Other algorithms and unknown header fields are explicit profile refusals, not silently ignored metadata.

## Resource and lifecycle bounds

| Resource | Fixed limit |
| --- | --- |
| Header Pickle | 16 MiB, plus the eight-byte size Pickle |
| Inventory | 50,000 entries, 32 directory levels, 4,096-byte logical member paths |
| Header integrity declarations | 200,000 block hashes |
| Index page | 1–256 rows; public response at most 1 MiB |
| Public member range | 1–65,536 bytes requested, default 16,384; an offset at EOF returns zero bytes |
| Whole selected member verification | At most 64 MiB per read, including range requests |
| ASAR member admitted as JavaScript | Complete member at most 1 MiB; existing graph source-count and 4 MiB total-source limits also apply |
| Concurrent admitted ASAR requests | Two; additional requests receive a busy refusal |
| Isolated worker | 768 MiB address-space ceiling, 12 CPU seconds, 20-second wall deadline, bounded stdin request and output |
| Controller commitment verification | Separate 20-second wall deadline and bounded stream reads |

The worker receives only a read-only inherited descriptor and a bounded structured request, with an empty environment. It uses the existing native syscall restriction on qualified Linux builds. It receives neither a source pathname to reopen nor runtime credentials. Parent-death binding is applied on Linux. Cancellation, worker output refusal and deadline failure all retain ownership of the original child until kill/wait completes. No durable job, resumable parser session or background analysis identity is invented for these request-scoped calls.

Inventory cost depends on the complete bounded header, not page length. Every member range revalidates the header and hashes the complete selected member; small delivery size does not imply small analysis cost. The implementation makes no cold-build, filesystem-latency, macOS qualification or full-application throughput claim. A future retained immutable snapshot may amortize those reads only after independently establishing its identity, authorization and recovery contract.

## Reproduction and independent reference

The ordinary Rust suite contains adversarial structure, integrity, admission, boundary and real shipped-MCP/worker tests. `tests/rea_asar_external.rs` verifies that identical ordinary and ASAR sources yield the same canonical graph and that links, unpacked members, stale identities and malformed descriptors are refused.

`scripts/rea-asar-reference.mjs` uses an explicitly selected installed `@electron/asar@4.2.0` as both the independent archive producer and archive consumer. It compares the consumer output to separately authored byte buffers before writing its reference. Fixtures cover packed/unpacked entries, nested directories, symlinks, empty content, Unicode, binary non-UTF8 payloads, exact four-MiB blocks and multi-block content. The package revision and source-file SHA-256 values are recorded. Node is a test oracle only, not a product dependency.

`tests/rea_asar_qualification.py` runs that reference, compares real MCP inventory and bounded member reads, checks explicit ASAR-to-AST acquisition, performs negative cases and reconnect observation, and stops an actually observed owned worker to distinguish cancellation from natural completion. The same harness separately observes the fixed 20-second deadline. It reuses the existing owned-process identity/pidfd helper, preserves original MCP requests/replies and checks the same original parent survives and serves the next request. A manual harness kill cannot count as a pass.

Run the external qualification with a frozen candidate runtime, its exact SHA-256, the installed reference package and a new absolute workspace:

```bash
python3 tests/rea_asar_qualification.py \
  --runtime /absolute/path/to/frozen/hepta-runtime \
  --expected-runtime-sha256 ACTUAL_COMPLETE_SHA256 \
  --asar-package /absolute/path/to/node_modules/@electron/asar \
  --repository /absolute/path/to/this/check-out \
  --workspace /absolute/path/to/new/qualification-directory \
  --allow-owned-child-signals
```

The harness records source inventories before/after and the actual candidate binary identity. Results apply to those identities and their stated platform. Passing this profile is not a declaration that all REA JavaScript/Electron workflows, retained views, source maps, runtime observations, signature checks or device families have been replaced.

## Recorded qualification

The Linux candidate passed 13 ASAR unit tests, eight graph regression tests, two shipped-worker/MCP tests, and all eight independent upstream/lifecycle gates. See [the source- and binary-bound qualification](qualification/asar-20261104-r2/README.md) for original evidence, exact identities, commands and observed limits.
