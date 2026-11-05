# X230 R25 preserved experiment

**Disposition: qualified, observation performance rejected, not adopted.**
The production `src` tree stays at accepted R24. See the
[full R25 report](../../../../docs/X230_OPTIMIZATION_20261105_R25.md).

## Source and qualification

- [Complete rejected source patch](rejected-candidate-02.patch) is against accepted R24; it includes the corrected fixture.
- [Exact qualified input map](reviews/qualified-source-map-02.json) binds all 221 source inputs.
- [Full qualification report](reviews/qualification-report-02.json), [isolated summary](reviews/isolated-tests-summary-02.json) and [native terminal](reviews/qualification-native-terminal-02.json) retain the actual attempt02 result: 1,653 passed, 34 ignored, zero failures or retries.
- [Original failed report](reviews/failed-qualification-report-01.json), [failed-attempt summary](reviews/failed-qualification-summary-01.json) and [failed native terminal](reviews/failed-qualification-native-terminal-01.json) preserve the original missing-fixture-policy failure.
- [Failed-archive verification](reviews/failed-qualification-archive-verification-01.json) covers its complete original archive, all members and the failed case output. [The full failed archive](evidence/qualification-01-failed.tar.gz) is included in this companion revision.

## Observation and owned transport

- [Complete campaign control](reviews/observation-control-02.json) records seven successful correctness/evidence stages and unchanged inputs, with `observation_gate_passed=false`.
- [Original gate summary](reviews/observation-summary-02.json) retains both C1 rejection reasons and every concurrency result.
- [Native independent analysis](reviews/native-analysis-02.json) retains 2,664 original calls, per-round metrics, resource observations and raw evidence audit identities.
- [Independent source/arithmetic review](reviews/observation-independent-review-02.json) recomputes the frozen gates and distinguishes pooled execution from direct fallback code.
- [Mac holder](reviews/mac-holder-02.json), [original native request](reviews/observation-native-request-02.json), [original start](reviews/observation-native-start-02.json), [terminal](reviews/observation-native-terminal-02.json) and [complete log read](reviews/observation-native-read-01.json) bind the one original campaign and complete owned-agent cleanup.

The prepared normal lifecycle ABBA and real direct-saturation cancellation fixture
were not executed. They remain pending for a candidate that passes observation
nonregression. The older C6 canary included in the observation run is a distinct
correctness check.

## External CI

- [Rust CI report](reviews/external-rust-ci-report-02.json), [independent terminal/inventory review](reviews/external-rust-ci-terminal-review-02.json) and [native terminal](reviews/rust-ci-native-terminal-02.json) bind exact workflow execution on qualified R25.
- [Python CI report](reviews/external-python-ci-report-01.json), [summary](reviews/external-python-ci-summary-01.json) and [native terminal](reviews/python-ci-native-terminal-01.json) retain all 18 original commands and their unchanged dependency subset.
- [Integration snapshot](reviews/integration-snapshot-02.json) preserves the previous Git head and actual hosted cancellation status. It does not claim hosted success for this evidence commit or any future candidate.

## Complete archive export

The one [native export request](reviews/export-native-request-02.json),
[start](reviews/export-native-start-02.json), [terminal](reviews/export-native-terminal-02.json),
[export report](reviews/export-report-02.json) and [independent exporter review](reviews/exporter-independent-review-02.json)
bind three completed X230 archives. The export itself ran no workload. It requires
the actual failed observation gate, records adoption as false, and rejects any
claim of nonexistent lifecycle output.

| Original archive | Bytes | SHA-256 |
|---|---:|---|
| [qualification-01-failed.tar.gz](evidence/qualification-01-failed.tar.gz) | 2,238,077 | `2382c0bf4de0c48a21d31fcc2e4952b6c2036cc2897612f77227b46682bc5091` |
| [qualification-02.tar.gz](evidence/qualification-02.tar.gz) | 2,450,580 | `82164857d78b965910fb5e1f8ae4d3d9769718d7fcafdd32bf2653eb1f1bd893` |
| [observation-02.tar.gz](evidence/observation-02.tar.gz) | 3,229,182 | `b463c80bb3897b4a96ce60d6cb7452ee23b521c50fe9c22048ea23169d180c7c` |
| [ci-02.tar.gz](evidence/ci-02.tar.gz) | 838,300 | `1faf3d0faa8bc2b76e91aa88fdfa6ae5211f47f5eb630fd4bf6a71dc7b0a0d43` |

All four archives are included in this companion tree. The [complete archive
verification](reviews/archive-integrity-and-semantics-02.json) covers all 7,939
payload members and 31 explicit body omissions in qualification02, observation02
and CI02. It binds the 221 actual qualified compiler inputs, original successful
native terminals and the unchanged observation rejection. The failed qualification01
archive has its own [independent verification](reviews/failed-qualification-archive-verification-01.json).

The [lossless assembly record](reviews/archive-assembly-report-01.json) retains
all 138 chunks: 56 previously transferred from the X230 and 82 recovered through
one original Mac-held SSH stream. The independent reconstruction of that complete
stream is 5,682,151 bytes, SHA-256
`d6949c07125f6c7f4d8356b7859b59f0f80f66c9d165d1daa15487ee27f275b1`.
It matches the original holder report and corrected decoder. The [transport custody
bundle](evidence/archive-transfer-custody-02.tar.xz) preserves the original API
payloads, all transfer timeouts and read-only resumption history, the first decoder
failure, its narrow correction, original native outputs and reviewed receiver code.
The original SSH holder and observation workload were not replayed.
The custody bundle contains 181 regular members and is 6,631,284 bytes, SHA-256
`cb5b1ad088ad300f61390dab27fc4abf285fee18414352ba93997403e4e6738e`.
Its [manifest](reviews/archive-transfer-custody-manifest-02.json),
[independent byte verification](reviews/archive-transfer-custody-verification-02.json)
and [Git blob receipt](reviews/archive-transfer-custody-proof-02.json) bind the
complete original API responses and three explicitly omitted duplicate archive bodies.

ELF payloads and private transport configuration/session wrapper bodies are omitted
explicitly; their exact original remote identities remain in archive manifests.
These omitted file bodies were not independently downloaded or rehashed locally.
Test logs, source, audits and native evidence bodies are preserved without selecting
only passing rounds. [Git blob publication identities](reviews/github-archive-blobs-complete-01.json)
match every original archive's byte length, SHA-256 and independently calculated
Git object SHA1.

The complete [Mac holder archive](evidence/mac-holder-02.tar.gz) is included here:
44,594 bytes, SHA-256 `45ec7e8ee551150e2435053e7fbf1eefea9f627ac74d9198cad6bb2bfdfc3765`.
Its [independent verification](reviews/mac-archive-verification-02.json) checks all
31 members and the original read/version/chunk chain. The [control binding](reviews/mac-x230-control-binding-02.json)
matches its exact native terminal, holder report, launcher and rejected footer to
the independently downloaded complete X230 control report. The three X230 archives are separately restored and verified above.

The [CI native operations bundle](evidence/ci-native-operations-02.tar.gz) retains
the original two requests, start/terminal responses, all log read pages, exact
request bindings and losslessly reconstructed stdout/stderr. It is 42,828 bytes,
SHA-256 `d48449e2f9ff77755abeda9c2301bbb2a51de6e48e73576c587318990df11659`;
the [manifest](reviews/ci-native-operations-manifest-02.json) records every member.
