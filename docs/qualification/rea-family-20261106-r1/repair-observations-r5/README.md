# R5 repair and source-freeze observations

This archive preserves the closed repair prechecks and their original failures for source commit
`fe3223cabbd2a8f1aa75a4ab57507bdb72291242`. It does not assert operation qualification.
The execution-input tree is `1a83f83cf62bf3d96e50c944722977b6971ffe686aecd131cab5e728dd802424`.

| Observation | Actual result | Scope |
| --- | --- | --- |
| Part A bootstrap, job `1a1b2444dec-fc05-7d3e` | Wrapper exit 1 | Invalid `SourceSelection` import; no tests started. |
| Part A corrected, job `1a1b245f180-fc05-7d46` | Wrapper exit 0 | Format check, 32 Python tests and 3 opaque-error Rust tests. Intermediate source tree, before Part B. |
| Part B initial, job `1a1b267f662-fc05-7deb` | Wrapper exit 0 | Format check and 47 finite Python tests. The incorrect Rust filter selected only the same 3 error-contract tests. |
| Part B corrected filter, job `1a1b26f9dd7-fc05-7e03` | Nextest exit 0; wrapper exit 1 | 31 actual Rust PASS rows and 2242 reported skipped; all 8 new regressions occur exactly once. The postprocessor regex was over-escaped. |

`assessment.json` is a new independent reading of the actual logs. The original Part B corrected
summary (`e4006e…`), stderr (`7128e7…`), failed wrapper output and prior independent assessment
(`9ca77c…`) remain byte-for-byte present. No command was rerun to replace a failure.

The archive contains all eight pinned private review archives, including the additional R4 state
consumer rejection-test package. Those offline tests do not prove that a future actual Provider
run produced all 23 required observations. It also preserves the original worker request, launch,
runner and terminal records for the four closed jobs; complete stdout/stderr are independently
matched to durable process-read observations. The exact inline shell source is extracted from
each authoritative request's `args[1]` without rewriting its text.

The actual matrix launcher `r5_freeze_and_matrix_r3.py` (`a7297d…`) and the matrix job's immutable
launch metadata are included. Its inline prelude independently reassessed the 31 tests before
`os.execv` entered that script. No unused wrapper version is claimed. The running matrix's
stdout, stderr, summary, final binary and resource outcome are excluded from this package.

`manifest.json` pins every archive member. Every retained nested archive and the complete outer
archive were bounded, rejected for links/special files/unsafe or duplicate names, extracted into
new private directories and read back. `derived/b3-to-r5-committed-change-manifest.json` identifies
each changed Git blob between the original base and the R5 source commit; it is separate from
later documentation/evidence commits. Selected working source matched the frozen snapshot before
and after sealing. The scripts in `tools/` reproduce the derivation with explicitly supplied roots;
they do not run Cargo, the runtime binary or an analysis engine.

These are finite prechecks and source/provenance observations. They do not replace the complete
nine-stage matrix, real ELF/Evidence or Ghidra tasks, cross-platform qualification, release costs,
or the remaining P0–P5 requirements. The 229-operation qualified count remains zero.
