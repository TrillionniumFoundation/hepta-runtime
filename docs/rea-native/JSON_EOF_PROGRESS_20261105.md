# Frozen REA 6.8.0 JSON EOF diagnostic candidate

This is a bounded P0/P1 implementation slice. Overall integration remains **HOLD / NO_GO**. The 229 npm tools retain their complete ledger denominators; no original public tool is promoted to fully qualified by this change.

## Identities

- Parent source: `57467bf38715853277e21b67a09865606464defa`.
- Implementation source: `fe5b43db5cd1ebead73cc11bbbbeeb65807d8ecc`.
- Original npm `rea-agents@6.8.0` tarball SHA256: `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`.
- Frozen Git source: `morluto/rea@93b8b82db70279e40f484114cff9dc1958dc14ee`. Its 234 static declarations are a different denominator from the 229 live npm tools.
- Original Node executable SHA256: `94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90` (v22.23.4).
- Existing 16-case original EOF fixture SHA256: `88d69efa06c7327cdb2429f9f28b3847c904b068f90feba8facdfb8bcfd1b450`.

## Change and boundary

The owned small-file reader now observes JSON prefix grammar with a fixed-size stack and UTF-16 positions. A diagnostic is exposed only after the value parser reports EOF, the reader has observed physical EOF, and the prefix is grammatical. The observer does not accept values, remove budgets, alter file identity or hashes, release cancellation ownership, or change the large-file parser profile. Non-EOF syntax and unsupported value representations still retain explicit gaps.

The old 16-case fixture previously asserted 7 exact errors plus 9 explicitly unsupported outcomes. Its test now requires all 16 original messages. The source-level unit test also covers chunk boundaries and negatives; passing that test is not a public MCP differential.

## Evidence at source freeze

The task-specific focused run completed `cargo fmt --all` and the all-features `rea_evidence_file` test filter with exit 0: 12 passed, 0 failed, 0 ignored, 2153 filtered out. This is development evidence, not the full matrix. An independently collected extended corpus has 116 cases (89 EOF, 14 non-EOF invalid, 12 valid JSON, 1 valid Evidence bundle); its complete original/native public differential and the full build matrix are separate evidence artifacts bound to this source tree.

## Gates that remain open

- Preserve raw transport bytes, unmodified JSON-RPC/result content, and parsed-content comparisons separately; normalization does not establish wire equality.
- No claim of complete schema, float/NaN/surrogate, authentication, concurrency, provider, cancellation, recovery, or format equivalence.
- The added observer does O(n) work on small valid JSON as well as invalid JSON. Same-behavior cost must be measured; no zero-overhead claim is made.
- Real external engine passes are bounded to their own prior source and binary hashes; they do not automatically qualify this candidate.
- GitHub publication is separately blocked by a previously recorded account-suspension 403. No alternate identity or transport is used to bypass that refusal.

The generated capability ledger binds the new module and deliberately keeps `--require-parity` failing while open tools remain.
