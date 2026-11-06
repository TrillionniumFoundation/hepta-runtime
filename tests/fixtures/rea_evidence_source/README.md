# Frozen REA Evidence source authentication fixtures

These are finite reference captures from the installed `rea-agents@6.8.0`
package corresponding to source commit
`93b8b82db70279e40f484114cff9dc1958dc14ee`.
The npm tarball SHA-256 is
`8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`.
The installed package was compared byte for byte with its tarball (2,398 files)
for the schema capture. The source module comments identify the REA MIT license.

## Reference data

- `schema-reference-r1.json`: one complete original APK Evidence seed, 109
  mutation recipes and the actual original safeParseEvidence outcome. Invalid
  cases retain both raw Zod issues, projected public issues and the exact
  describeValidationFailure result. Ten cases succeed and 99 fail.
- `file-reference-r1.json`: 18 actual readEvidenceFileSource calls over newly
  owned temporary files. Each stores its original JSON input, selected ID,
  absolute path, original typed error and complete projected public error.
  Five cases succeed and 13 fail. Cases cover one/zero/multiple records, exact
  selection, duplicate IDs, malformed records, canonical manifests and order,
  authentication of an unselected record, bare-record authentication, the own
  records-property discriminator and the 2,048-byte ID preview.
- `file-reference-root-order-r1.json`: root object key order extracted from the
  pinned Node-produced JSON fixture text with an insertion-preserving parser.
  This is trusted parsing metadata for these exact fixture bytes, not a claimed
  order reconstructed from serde_json's sorted map.
- `producer/`: original capture requests, Node runners and qualification
  receipts, preserved without rewriting their historical paths.
- `provenance.json`: source hashes, original process terminals and the component
  test terminal. The original failed component attempts remain in the external
  evidence directory; the accepted test result is component-r4.

The sibling Rust tests compare all 109 projected issue arrays and descriptions.
For the 18 file cases they compare selected semantic IDs, error type, complete
selector/bundle messages and bare-record content issues. The complete original
public projections remain in the fixture for the runtime service's integration
tests; this pure helper does not project the final public Failure envelope.

## API and scope

`authenticate_inline(Value)` and
`authenticate_file(Value, path, selected_id)` consume the owned JSON and return
`Arc<Value>`. Their `_with_order` variants accept an optional resolver whose
paths are relative to that exact JSON root, including `records/index` for bundle
members. The resolver must come from the actual parser, never caller-supplied
metadata. It must list every member exactly once when multiple unknown fields
need ordering.

The helper validates frozen Evidence fields and refinement order, profile
digest/provider binding and semantic identity. It preserves the special
obsolete null-relationship-coverage diagnosis. It authenticates every record
before selecting from a canonical bundle. Selection moves the selected record;
large raw and normalized payloads are not cloned. Tests check that owned payload
storage survives inline and bundle authentication, and compare the new borrowed
identity calculation with the shared canonical stream on a real original seed.

Errors remain typed:

- `InvalidRecord { issues, description }`: record-relative issues. Inline
  callers prefix source/evidence; file callers use the original wrong-kind
  Evidence-file error and content issues.
- `InvalidBundle { message }`: original complete bundle-authentication message.
- `Selection { message }`: original AnalysisInputError message for
  source/evidence_id.
- `ProfileGap { feature }`: an explicit implementation/profile boundary.
- `Internal { message }`: an unexpected implementation failure, distinct from
  caller-correctable source facts.

This implementation deliberately exposes profile gaps for nonempty residual
unknown histories, process-capture payload authentication, unavailable/invalid
ordering metadata for multiple unknown fields and semantic JSON members deeper
than 127 (the existing shared canonical profile). The original JSON value
boundary allows depth 1,000. A profile gap does not establish corrupt Evidence.

File root admission, stable descriptors, strict UTF-8 and JSON parsing,
JSON.parse-compatible duplicate-key/number behavior, resource admission,
cancellation and filesystem/cleanup error typing belong to the caller. The
original 8 MiB native-JSON parsing threshold is not a file size limit. The caller
must check cancellation around authentication and retain its admission/lease
until blocking work completes. This helper does not establish provider truth or
the full REA Evidence import contract.

## Validation

Component tests ran with Rust 1.95.0, edition 2021, offline, two build jobs and
the exact root lockfile package identities. The mini crate compiled this actual
production module and exact pinned shared canonical source/function bodies; it
did not stub the identity calculation. Seven unit tests passed, including all
127 original finite reference cases; strict Clippy passed with -D warnings.
Source hashes matched before and after. This is component qualification.
The parent runtime still must wire the module and validate real MCP, file
admission and cancellation behavior.
