# Native APK/JAR manifest declarations

`rea_inspect_application` reads one fixed manifest entry from an admitted local archive. APK mode reads exactly `AndroidManifest.xml`; JAR mode reads exactly `META-INF/MANIFEST.MF`. The tool does not infer the format from the filename.

The implementation reuses the runtime's classic ZIP directory/local-header parser and descriptor-relative workspace admission. It does not introduce a second archive parser, daemon or external package tool. The selected entry is captured during the complete-archive SHA-256 pass on the same file descriptor, decoded by the pinned Rust `flate2` dependency, and checked with `crc32fast`. Declared output size, complete raw-deflate stream consumption and CRC32 must all match.

## Interface

```json
{
  "path": "/configured/workspace/owned.apk",
  "kind": "apk",
  "collection": "components",
  "offset": 0,
  "limit": 64,
  "expected_sha256": null
}
```

| Field | Meaning |
| --- | --- |
| `path` | Absolute regular file beneath a configured controller workspace root; symlink traversal is denied. |
| `kind` | Required `apk` or `jar`; chooses the fixed manifest name. |
| `collection` | `summary` (default), `attributes`, or APK-only `components` / `permissions`. |
| `offset` / `limit` | Zero-based row offset and 1–256 rows; default limit 64. Summary requires offset zero. |
| `expected_sha256` | Optional lowercase full-archive SHA-256 on the first page, mandatory on every continuation. |

Every report distinguishes the full archive SHA-256 from the decompressed manifest SHA-256, includes the selected ZIP member's payload offset and CRC32, and marks signature validation and other members' payload validation as unperformed. The response is an analysis report, not a retained REA evidence record.

## APK coverage

The parser reads standard Android binary XML chunk structures, a UTF-8 or UTF-16 string pool, the optional resource-ID map, namespace events, element starts/ends, and typed attributes. It validates chunk extents, string indices and encodings, namespace and element matching, and duplicate attributes. It preserves a typed attribute's raw text, type/data representation, namespace URI, resource ID when present, and byte offset.

The summary exposes literal package/version declarations, SDK declarations, and counts. `components` includes direct application children named activity, activity-alias, service, receiver or provider. `permissions` includes direct manifest permission uses/declarations. `attributes` lists attributes on all parsed elements with the element name/depth, source chunk offset and source line. Relative component names remain literal. Unqualified attributes are not mistaken for attributes in the Android namespace.

These are captured declarations. The runtime does not load `resources.arsc`, resolve framework resource IDs, decide effective permissions or exported behavior, validate DEX/classes, establish installability, or authenticate a signer. Unknown value types retain their numeric type and data. CDATA is structurally checked and counted, without interpreting it as manifest semantics.

This implementation accepts a bounded subset: standard 8-byte XML, 28-byte string-pool and 16-byte node headers; 20-byte attribute structures; unstyled string pools. Unsupported extensions, styled pools and unknown chunks produce explicit errors.

## JAR coverage

The parser reads the main section of `META-INF/MANIFEST.MF`, beginning with `Manifest-Version` and ending at the first empty line. CRLF, LF and CR physical line endings are supported. Continuation bytes are joined before UTF-8 decoding, including a code point split across physical lines by the actual `jar` writer.

Attribute names are validated and duplicates are rejected case-insensitively. Rows retain original name spelling, unfolded value, first physical line and byte offset. Summary values include Main-Class, Automatic-Module-Name, Class-Path and Multi-Release declarations when present. The parser does not follow Class-Path, load a class, read per-entry sections, validate signatures or interpret a module descriptor. Remaining per-entry bytes are counted as unparsed.

## Hard limits

| Resource | Limit |
| --- | --- |
| Archive bytes | 512 MiB |
| ZIP entries | 50,000, inherited from the shared ZIP indexer |
| Selected compressed / uncompressed manifest | 4 MiB each |
| Selected compression methods | Stored (0), raw deflate (8) |
| JSON response | 1 MiB |
| Concurrent application workers | 2; the blocking worker retains its slot after waiter cancellation |
| Stream/parser work deadline | 240 seconds, checked between bounded work units |
| AXML strings / individual decoded string | 65,536 / 64 KiB |
| AXML total decoded strings / referenced text | 8 MiB / 32 MiB |
| AXML elements / attributes / depth | 20,000 / 20,000 / 64 |
| AXML attributes per element / active namespaces | 128 / 64 |
| Retained parsed declarations | 16 MiB of serialized JSON |
| JAR main attributes / unfolded value | 256 / 65,535 bytes |
| JAR physical main-section line | 72 bytes, excluding the newline |

The existing ZIP parser rejects duplicate member names globally, overlapping file ranges, ZIP64, multi-volume archives and unsupported name encodings. Its bounded AAPT2 compatibility accepts the Android writer's local four-byte alignment form only for unencrypted stored members: the entire local extra region must be 1–3 zero bytes and must place the payload on a four-byte boundary. This is not general ZIP alignment support. Central-directory extras and all other local extras retain strict TLV parsing; mixed or truncated fields are not treated as padding. Only the chosen manifest payload is decompressed and CRC-verified. Same-descriptor metadata checks detect ordinary concurrent changes; a privileged writer restoring metadata while racing the read is outside this guarantee. No archive member is extracted to a filesystem destination.

## Reproducible owned fixtures and verification

`tests/fixtures/rea_application/` contains owned Android and Java sources, manifests, actual tool-generated packages, aapt's XML tree output and `provenance.json` recording complete generation commands, tool outputs, sizes and SHA-256 values.

Fixture generation used this task's separate checkout on the development host, with Android build-tools 35.0.1 (`aapt` and `aapt2`), Android platform 35 resources, and `javac` / `jar` 21.0.12.1. The Java class targets release 17. Neither the Android packages nor the compiled Java class was executed or installed. Both actual APK writers emitted UTF-16 string pools; a separate explicitly synthetic binary XML fixture tests UTF-8 and supplementary characters.

Unit tests exercise these real packages, stored and deflated manifest equivalents, full-archive continuation identity, CRC mismatch, exact deflate boundaries, compressed/decompressed/source/output budgets, duplicate ZIP names, fixed-name selection, unsupported methods/encryption, malformed binary XML, Unicode errors, namespace identity, repeated-offset expansion and depth limits, JAR continuation/duplicate/encoding errors, and root/symlink denial.

`tests/rea_application_external.rs` starts the shipped stdio MCP binary under its own temporary test policy with a remote host that cannot execute. It checks tool discovery/read-only annotation, real APK/JAR calls, continuation identity, wrong-root rejection, restart continuity, and unchanged original packages. Test execution receipts are recorded separately with the source and binary identities; fixture generation alone does not establish that those tests passed.

## Format references

- [Android framework ResourceTypes.h](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/libs/androidfw/include/androidfw/ResourceTypes.h): AXML/string-pool/resource-value structure definitions. Inspected blob: `e330410ed1a0890be266da0e62a3e6d1a25a3cdc`.
- [Java 25 JAR specification](https://docs.oracle.com/en/java/javase/25/docs/specs/jar/jar.html): main-section structure, physical lines, continuation and attribute names.
- [Android 15 AAPT2 archive writer](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-15.0.0_r1/tools/aapt2/format/Archive.cpp#L145-L159) maps its alignment flag to `ZipWriter::kAlign32`; [the official ZIP writer](https://android.googlesource.com/platform/system/core/+/fdd67a54ec43b47616893f8138d6d7029d14513b/libziparchive/zip_writer.cc) writes the resulting raw zero padding in the local extra region.
