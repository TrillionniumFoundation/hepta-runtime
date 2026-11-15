# Recorded-core original-reference differential

This harness qualifies one narrow contract: the JSON payload returned by the
unchanged `inspect_core` function in REA `rea-agents@6.8.0`, and the stable typed
failures observed through the original helper. It retains complete Python and
native envelopes. It does not qualify the complete Python helper, decoder
runtime, public Provider, or MCP lifecycle as replaced.

## Fixed reference

The reference installation must contain these exact files in one directory:

| File | SHA-256 |
| --- | --- |
| `recorded_crash_impl.py` | `8dd89f64d7fa1a218b7def48c02a1e3bddfe8d2a47a2816e2e06441b9d394bb8` |
| `recorded_crash.py` | `1ff9358501ffd02af6e33d1ec759d2018171c33c749049bf3599335eca7a41bb` |
| `decoder_runtime.py` | `46a066d55314f0a3fa72b2ac14ddcd18bca2c21f975115347cefd2286741e410` |

Use an isolated Python environment with `pwntools==4.15.0`, `pyelftools==0.33`,
and `unicorn==2.1.2`. The capture records the actual interpreter, platform,
resolved package versions, distribution metadata hashes, and an optional full
pip download report. Do not replace these packages with stubs or local parser
ports. The isolated environment is a newly resolved environment; transitive
dependencies and its host identity are recorded, not asserted to match an
unobserved historical installation.

## Execution

All output directories must be new and outside the source/reference trees.
The commands below use explicit absolute paths assigned by the operator.

```sh
python3 scripts/rea_recorded_core_corpus.py --output "$CORPUS_DIR"
python3 scripts/rea_recorded_core_differential.py reference \
  --corpus "$CORPUS_DIR" --reference-root "$REFERENCE_HELPER_DIR" \
  --python "$PINNED_PYTHON" --pip-report "$PIP_REPORT" \
  --output "$REFERENCE_CAPTURE_DIR" --jobs 2
python3 scripts/rea_recorded_core_differential.py native \
  --corpus "$CORPUS_DIR" --reference "$REFERENCE_CAPTURE_DIR" \
  --runtime "$RUNTIME" --runtime-sha256 "$RUNTIME_SHA256" \
  --source-binding "$BUILD_BINDING" --output "$NATIVE_CAPTURE_DIR" --jobs 2
```

The corpus generator writes bytes and descriptions, never predicted outputs.
It covers both admitted architectures, supported OSABIs, empty files/notes,
header and table widths, `PN_XNUM` through section and string-table factories,
machine-specific segment types, out-of-range and overflowing fields,
overlapping/duplicate notes, exact/opaque/invalid owners, UTF-8 replacement,
register and signed metadata widths, note alignment, descriptor extensions,
truncations, unknown union meanings, and seeded mutations. All original rows
remain in their original order, including failures and mismatches.

## Two original executions

The direct API capture executes the byte-exact original implementation as a
module and invokes its original `inspect_core`. It applies and records actual
soft resource limits before importing the decoder dependencies. It preserves
uncaught exceptions separately.

The whole-helper capture starts the original `recorded_crash.py` in a fresh
Python process for every fixture. Each private directory retains the original
request, reply, `limits.json`, failure marker if any, stdout, stderr, and exit
status. The unchanged `decoder_runtime.py` appends its actual effective-limit
sentence to successful payloads. The harness checks that measured sentence
and original profile against the separately observed API payload; the raw
helper output is never edited or discarded.

## Native comparisons and boundaries

The native phase verifies the runtime digest before and after the run. It
retains every frame, stdout, stderr, exit status, native profile, snapshot and
reported resource limits. Parser payloads compare as exact JSON values; list
order and types matter. Typed failures compare both reason and message. A
first-difference diagnostic supplements complete original and native rows.
An accepted reference case rejected as unsupported is a mismatch.

Whole Python and native envelopes are also compared literally and the result
is recorded. The native implementation has its own genuine profile and
resource boundary. A difference there is not transformed into full-helper
parity. Input/output-cap refusals and strict-frame protocol cases are separate
native boundary observations with all raw data retained.

One owned launcher also applies genuinely tighter inherited soft limits
(1.5 GiB address space, 10 CPU seconds, 32 MiB file size, 32 open files, zero
core size, or an already tighter inherited value) before executing the same
bound native binary. The raw pre-exec receipt and the native observed limits
must agree exactly. This exercises preservation of actual inherited limits;
it is not a comparison against an invented Python resource profile.

Output-budget cases measure the complete native envelope including its newline
and actual reported budget fields. They test the smallest observed successful
boundary and nearby values, plus budgets too small for a normal failure reply.
For a native child held on partial input or a missing EOF, the external harness
keeps a wall deadline, kills only its own newly created process group, reaps the
child and drains both streams. This proves this harness's ownership behavior;
the worker CPU limit alone is not a wall timeout, and these rows are not public
Provider cancellation or recovery qualification.

The summary and raw JSONL files are the evidence. A zero mismatch count can
support the stated parser domain only. Source publication and complete six-work-
package qualification require the enclosing combination's separate gates.
