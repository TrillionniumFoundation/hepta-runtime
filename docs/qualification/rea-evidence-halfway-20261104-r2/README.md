# REA Evidence: ECMAScript halfway-number regression

This change closes a demonstrated numeric canonicalization defect in the native
Evidence subset. It does not qualify the complete REA Evidence schema, all
IEEE-754 inputs, or all 229 upstream tools.

Base commit: `1d9ea7e7e7a1625c611d5f6e037a1ed9d57379d4`.
The source hashes in `source-before.json` and `source-after.json` are identical
for the complete fixed validation run.

## Defect and repair

The old renderer used Rust `f64::Display` to obtain shortest decimal digits.
A shortest round-tripping representation is insufficient: ECMAScript also
specifies which equally close decimal representation to choose. For binary64
bits `431548edc45ad881`, Rust Display produced
`1497790137415200.3`, while Node's `JSON.stringify` produced
`1497790137415200.2`. Both decimals round to the same binary64 value, but only
the latter matches the producer's canonical bytes. The discrepancy changed
analysis-profile and Evidence digests and rejected legitimate producer records.

The repair obtains shortest digits from the already locked
`serde_json 1.0.151` serializer, which uses `zmij 1.0.23`, and retains the
existing explicit ECMAScript fixed/exponential notation rules. The dependency
graph is unchanged. There is no newly implemented floating-point conversion
algorithm and no Node dependency in the runtime operation.

The always-on regression has 20 independently observed bit patterns. The
published-package oracle generator also includes those values. The historical
418-record fixture remains intact and was rerun separately: its prior passing
result was valid for that corpus, but that corpus missed these ties.

Primary specification: [ECMAScript Number::toString, step 5](https://tc39.es/ecma262/#sec-numeric-types-number-tostring).
The recorded Node behavior is the independent executable oracle for this run.

## Completed verification

| Check | Observed result |
| --- | --- |
| Old implementation with the new always-on regression | Exactly 1 test ran and failed on bits `431548edc45ad881` |
| Fixed Evidence unit module | 14 passed; 4 external-oracle tests explicitly ignored in this invocation |
| Explicit broad finite-number oracle test | 1,052,304 finite rows passed, including parsing round trips |
| Actual npm-generated numeric Evidence | 438 records accepted by upstream first, then native verifier |
| Original historical npm numeric corpus | All 418 still pass |
| Actual npm schema-negative corpus | All 20 invalid, hash-consistent records rejected |
| Actual npm ELF Evidence | Passed |
| Frozen old production binary, public stdio MCP | 418 successes; exactly 20 halfway records rejected with `analysis_profile digest mismatch` |
| Fixed production binary, public stdio MCP | All 438 succeeded; zero rejections or mismatches |
| Formatting | `cargo fmt --all -- --check` passed |
| Clippy | All features and targets passed with warnings denied |

The fixed binary is the optimized **dev** build, SHA-256
`90beb46f50591d39c241d3b19636cdd85f1fb088cc0f2e01674e87366c6ccbd1`.
The old frozen release is
`4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d`.
Both actual MCP runs checked the selected binary before and after execution and
exited normally. These receipts do not qualify a later combined release; rerun
the public MCP script against that exact frozen release.

`before-fix-lib.json` is the real failing unit test receipt.
`before-fix-mcp.json` records all 20 false rejections.
`after-fix-mcp.json` and `verification.json` record the fixed behavior.
The broad test was explicitly selected with `--lib` and `--ignored`;
the wrapper requires the named test to occur, so zero selected tests cannot
count as a pass.

Two incomplete attempts remain visible in `attempts.json`: an initial
`--bin` invocation selected zero tests, and an initial full old-binary MCP
attempt exceeded its 300-second command budget. Neither is qualification.
The complete old-binary run used the same test and expectations with a
900-second command budget.

## Independent inputs and identities

The installed oracle is `rea-agents@6.8.0`, compared byte-for-byte against the
authenticated local tarball: all 2,398 regular package files matched, with zero
mismatches. The tarball SHA-256 is
`8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`;
`package-attestation.json` also records its SRI and package.json hash.
The generator invokes the real compiled `createAnalysisProfile`,
`createEvidence` and `parseEvidence` functions.

The broad numeric corpus uses Node **22.23.4**, V8
**12.4.254.21-node.57**, and fixed xorshift64 seed
`7265615f65766964`. Its 1,052,304 finite rows are intentionally **not deduplicated**:
they cover all finite binary exponents with selected mantissas and both signs,
decimal-power neighborhoods, halfway neighborhoods, golden boundaries and
999,527 finite outcomes from 1,000,000 deterministic random bit patterns.
Non-finite values are counted and excluded. These finite samples are not an
exhaustive proof for the entire binary64 space.

The TSV hash is
`c02f4b12d3ed29c2a1598328fd5f7d9837a530df0f94b4330be554dea23d8846`.
The 438-record JSON file hash, including its final newline, is
`e72cf0239101d1bc2365df8215150162839571b29a3de39d0ac2b4386afd4fa4`.
The existing npm manifest convention hashes the JSON payload without that
newline and therefore reports
`14df818d4f4cb68e9b13a86b5802d2b1abd3b703951d79506ba872b5114a563c`.

The repository retains the manifests, compact receipts and one genuine
halfway Evidence record in `halfway-example.evidence.json`. The large TSV,
complete transcripts, builds and regenerated full corpus stay outside git.
`artifact-manifest.json` binds the archived machine-readable evidence.

## Reproduce and qualify a combined binary

Run from the repository root with an authenticated published package installed
under `REA_NPM_PREFIX/node_modules/rea-agents`. The checked local installation
used for this run is
`/home/qian-qi/work/hepta-rea-reference-20261103/install`.
Use a fresh output directory, because the bit-pattern generator refuses to
overwrite its TSV.

```sh
export REA_NPM_PREFIX=/home/qian-qi/work/hepta-rea-reference-20261103/install
export REA_NUMBER_OUT=/tmp/rea-evidence-number-reproduction
mkdir "$REA_NUMBER_OUT"

node scripts/rea-number-reference.mjs "$REA_NPM_PREFIX" "$REA_NUMBER_OUT"
node scripts/rea-number-bit-reference.mjs "$REA_NUMBER_OUT" 1000000

cargo +1.95.0 test --locked --offline --all-features --lib \
  rea_evidence::rea_evidence_tests -- --nocapture

REA_REAL_NUMBER_CASES_TSV="$REA_NUMBER_OUT/number-cases.tsv" \
  cargo +1.95.0 test --locked --offline --all-features --lib \
  extensive_ecmascript_finite_number_corpus_matches_native_renderer \
  -- --ignored --nocapture

REA_REAL_FLOAT_EVIDENCE_JSON="$REA_NUMBER_OUT/REA_6_8_0_FINITE_NUMBER_EVIDENCE.json" \
  cargo +1.95.0 test --locked --offline --all-features --lib \
  real_npm_fractional_reference_evidence_matches_native -- --ignored --nocapture

REA_REAL_INVALID_EVIDENCE_JSON="$REA_NUMBER_OUT/REA_6_8_0_INVALID_EVIDENCE_SCHEMA.json" \
  cargo +1.95.0 test --locked --offline --all-features --lib \
  real_npm_rejected_schema_matrix_is_independently_rejected_by_rust \
  -- --ignored --nocapture

python3 scripts/rea-evidence-number-mcp.py \
  --binary "$REA_QUALIFIED_BINARY" \
  --binary-sha256 "$REA_QUALIFIED_BINARY_SHA256" \
  --corpus "$REA_NUMBER_OUT/REA_6_8_0_FINITE_NUMBER_EVIDENCE.json" \
  --output "$REA_NUMBER_OUT/mcp"
```

Set `REA_QUALIFIED_BINARY` and `REA_QUALIFIED_BINARY_SHA256` to the actual
frozen candidate. The harness refuses a changed fingerprint and creates its
own isolated MCP policy, workspace and state. Allow at least 900 seconds for
the whole MCP harness on a loaded qualification host. Do not add expected
rejections for a fixed candidate.

For the old frozen binary only, the demonstrated baseline uses
`--expected-rejections 32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51`.
An arbitrary failure does not satisfy this baseline; each expected rejection
must contain a digest mismatch.

Historical 418-record and ELF fixtures used here remain in
`/home/qian-qi/rea-ledger-inputs-20261104-r1/oracle/`.
The respective ignored tests use `REA_REAL_FLOAT_EVIDENCE_JSON` and
`REA_REAL_EVIDENCE_JSON`. This work changes no full-schema qualification flag
and does not broaden bounded parsing or provider support claims.
