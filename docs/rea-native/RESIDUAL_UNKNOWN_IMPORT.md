# Residual unknown authentication for Evidence import

This module implements the residual-unknown domain in the selected published
`rea-agents@6.8.0` reference. It validates normalized revisions, complete revision
histories, Evidence and unknown references, verified-resolution requirements,
and dependency cycles among current heads. Public file admission, cancellation,
transactional session publication, and MCP errors belong to the import handler.

The source contract is the MIT-licensed `dist/domain/residualUnknown.js`
(`28f97f7b0d5afc95ec65d5eb90295ad97aad140028877246dadfb4abd6603433`)
and `dist/domain/evidenceBundle.js`
(`24796cd112032363d9da0c8f9fc40c46364154e76e21084dfc46d640456f6314`).
The published npm package, its original Git reference, and later upstream
revisions are separate identities; this does not assert their equivalence.

## Preserved behavior

- ECMAScript whitespace determines trimming and stable question identity.
  Internal question whitespace remains revision content. Rust Unicode
  whitespace is deliberately not used as a substitute.
- Fixed schema objects omit an own `__proto__` key. Other unknown keys retain
  their original diagnostic order. This does not strip arbitrary JSON payloads.
- Shape validation preserves the order and multiplicity of original issues,
  including length checks that run after string or array type failures.
- Revision digests bind normalized revision content. Unknown IDs bind the
  immutable domain, collapsed question, scope digest, and optional comparison
  conclusion scope.
- Histories are checked before references. Verified resolution requires an
  eligible supporting observation, the required authority/confidence and
  environment, and no retained contradiction. A mutation record alone cannot
  verify resolution.
- Dependency cycles are checked on current heads. Historical relationships
  removed in later revisions and non-dependency cycles remain allowed.
- The graph walk is iterative. Verified-resolution membership uses a borrowed
  set instead of rescanning the complete supporting list for each resolution
  ID. Qualification still follows the original resolution-ID order.

`rea_evidence_source_length.rs` reproduces the original Zod length guard and
JavaScript numeric comparison for JSON-valued lengths. Strings use UTF-16 code
unit counts; malformed objects can produce an additional `unknown`-origin
length issue. A non-callable own `toString` can make the original schema throw.
The child records a dedicated exception marker without panicking or fabricating
validation issues; the public parent handler must map that marker to the actual
original plain-text tool failure.

## Reference evidence and scope

`scripts/rea_residual_unknown_reference.mjs` runs the unmodified selected npm
modules. It verifies the two domain source pins, records seven REA source
identities and Zod check/utility/locale identities before and after execution,
and records the actual Node executable identity. It refuses to overwrite a
prior receipt.

`tests/fixtures/rea_residual_unknown/reference-r2.json` contains 328 shape cases,
27 complete-history/reference/resolution graph cases, and 130 length-check
cases. The length corpus separately records eight original coercion exceptions.
The fixture SHA-256 is
`cd1e31a24d47bc01d700fbb13558635e5b7a47d5a06b5b795c32b812456c9ea4`.

Development validation used the exact child modules, a recorded pending parent
source snapshot, the committed process-capture authenticator, and the actual
canonical writer bodies in a small offline Rust harness. Its ten tests cover
the two residual-domain gates, the length gate, and seven process-capture unit
gates. The harness uses the same Rust 1.95 and edition 2021 as the runtime.
Earlier failing normalization/length probes and the harness's initial edition
2024-only Clippy failure remain recorded. A corrected harness result does not
replace the final full-crate matrix.

These finite domain results do not establish public import parity, engine or
device coverage, complete multi-host recovery, production cost equivalence, or
replacement qualification for all 229 reference tools. The final public gates
must bind this module and its parent integration to the same frozen runtime
binary and toolchain.
