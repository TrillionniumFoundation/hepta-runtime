# Protected PDF modification policy

`pdf_security` keeps cryptographic signature integrity, certificate anchors, modification policy, and signing of a new revision as distinct questions. Prior `inspect`, AES-256 derived-copy and unsigned metadata behaviors remain available. Two additional actions are implemented by the fixed offline worker:

- `validate_policy` runs revision difference analysis using pinned pyHanko 0.37.0, including DocMDP and FieldMDP where present. It binds each signature's byte range to the existing independently checked detached-CMS result. Parsing disagreement, unavailable policy analysis, tampered signed bytes and forbidden post-signature changes cannot become a successful combined policy result. Optional pinned public trust roots retain the original certificate-chain contract.
- `fill_form_copy` fills existing ordinary text fields into a distinct incrementally written PDF. It requires a source fingerprint, output fingerprint/create-only expectation, explicit acknowledgement that the new revision is unsigned, and SHA256-pinned public certificate anchors. The original certified source must pass cryptographic, chain and policy checks and admit form filling. The generated output is independently validated again; changed signature bytes, locked fields, forbidden differences or unexpected field values prevent publication.

## Meaning of successful form filling

A certification signature may permit filling form fields without permitting arbitrary page-content changes. In an accepted derived copy the original signed bytes remain the exact prefix, its signature can still validate, and its policy can permit the form change. This does **not** mean the old signature newly signs the filled values, nor that the entire current revision is covered by that original signature. `new_revision_is_signed` remains false. No signing keys are accepted by this interface.

The policy is stricter than the upstream default: overwriting existing appearance-stream objects is not allowed. Generated appearances use fresh object references; the old locked-field objects are retained. This avoids a reproduced upstream in-place-appearance-rule false positive without admitting additional modifications.

The output result names changed fields but does not repeat raw field values or password contents. Byte-range integrity/trust results and modification-policy results are returned separately. A missing certificate anchor does not acquire trust from the document itself. Revocation checking, trusted signing time, certificate-purpose policy and legal validity are not inferred from successful difference analysis.

## Rendering and input boundaries

The first admitted editing contract covers existing direct single-widget, single-line AcroForm text fields with printable ASCII values and no active form actions. Additional Unicode font/glyph coverage and hierarchical or repeated widgets are not yet qualified; these inputs fail before publication. Read-only, password, file-select, rich-text and multiline fields, XFA and encrypted certified-form edits require separate support and are refused instead of being silently rewritten. No form flattening, page deletion or signature replacement is performed. Implicit network lookups are not performed by revision difference analysis. Existing worker memory, execution and output bounds still apply.

Test fixtures must use disposable generated certificates/keys and documents, never real user's signing material. Acceptance checks cover unmodified certification, permitted form filling, a no-changes policy, locked fields, forbidden page modifications with intact older CMS signatures, wrong anchors, unsigned sources, stale file fingerprints and create-only output. Derived forms must also be rendered and checked for visible values; reading a `/V` dictionary alone is insufficient.

## Configuration and release qualification

The parser update is prepared in a separate versioned environment; the active environment is retained until candidate tests pass. The runtime's remote path continues to use existing configured file roots and version/hash-checked native transfer. Password files stay on that established private-file path. The new actions do not add shell, sudo, network or host authority.

A release is only deployed after local tests, same-artifact real-host protocol checks and source attribution. The qualification receipt records actual installed binary and parser paths, and any missing lifecycle work independently. In particular, successful PDF policy work does not prove cold power removal, controller-host restart or process-tree memory migration.

## Upstream references

- pyHanko validation and difference-analysis contract: https://docs.pyhanko.eu/en/latest/lib-guide/validation.html
- DocMDP and FieldMDP semantics: https://docs.pyhanko.eu/en/latest/lib-guide/sig-fields.html
- Pinned pyHanko package: https://pypi.org/project/pyHanko/0.37.0/
- pypdf forms and appearance handling: https://pypdf.readthedocs.io/en/stable/user/forms.html
