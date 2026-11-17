# extract_lines public input domain

This package supplies request bytes and owned fixture input descriptions. It
does not implement a tool, produce an expected wire/result, run HIA or Rust, or
claim a public qualification result. `SOURCE_CHECK.json` records source and
input generation checks only.

Target: `d3d75c30719db966b004756f610007a7c723729e`. Intended successor graph:
`a521066dfa07db38e6a22bd2f03d1dae3c203cc2`, aligned with default111 production
source `fa2aed97cf22b720d85bd8d08b720aeadba3c4d6`. Neither graph membership nor
these input counts establishes a passed public comparison.

## Complete inputs

| Domain | Legacy | Modern | Input contract |
| --- | ---: | ---: | --- |
| Typed objects | 189 | 189 | Exact same argument bytes; different SDK context framing |
| Shared two-session chain | 35 | 35 | extract, four TextEditor commands, cross-session undo, separate cache seeds |
| Two-session workdir context | 13 | 13 | First typed/valid call, later changed metadata, absolute shared keys |
| Ordinary real stdio | 22 | 20 | 20 tool calls; legacy additionally has initialize and initialized |
| SDK protocol scenarios | 48 | 48 | Metadata, Map/params/name shape, raw IDs, notifications, recovery |
| Real EOF scenarios | 5 | 5 | Complete request, complete/no-LF tail, partial tail, immediate half-close |

These are 622 input rows or scenarios, **not** an expected response or dispatch
count. Initial messages and scenario substeps are retained separately. The
complete existing body domain (153 pairs / 175 operations) remains separate;
none of its result/status fields was copied into this input package.

Typed objects cover all 15 nonempty subsets of missing required fields;
String-versus-other-type paths; absent/null optional end; endpoint values,
numeric strings and line tokens; exact decimal JSON number spelling; duplicate
keys; unknown fields; and escaped keys/values. Duplicate input keys remain raw
bytes. The actual SDK Map boundary and parameter extractor decide their
interpretation; no private Value reference replaces that SDK boundary.

The shared chain includes extract followed by undo through the other session,
TextEditor replacement followed by extract and two undos, creation of a source,
extract into it, delete/undo, same-file extraction, alternate spellings of one
file key, and ordinary calls after rejected inputs. Cache seeds belong to their
declared sessions. Capture both complete caches, both session states, complete
shared history/lock observations and full filesystem state before/after each
call. Serial lock observation does not establish WAIT or concurrent cancellation.

## Retained framework adapters

The four framing helpers preserve original Batch text and AST after only
`batch-public-corpus` → `extract-public-corpus` and default tool `batch_edit` →
`extract_lines`. `line_hash` preserves original body text and AST exactly; it
only supplies input line tokens. `PROVENANCE.json` binds original files and
exact target Rust spans.

Retain the actual private two-session public-selector call, original
ToolCallContext / AsyncMethodAdapter / serve(duplex), seed and observation code.
Adapt only the input provider:

- `typed_rows(fixture)` returns 189 typed objects.
- `session_rows(fixture, modern=...)` returns 35 ordered calls.
- `context_plan(fixture, modern=...)` supplies setup, actual initialization and
  13 ordered calls. Apply setup before initialization.
- `wire_for_row(row, index, modern=...)` uses existing framing and ID `1000+index`.
- `all_inputs(fixture)` includes the exact startup plan for every domain. The
  modern typed lane initializes unused session 1 in the retained legacy manner;
  session 0 is admitted through actual inline requests.

Use the plan's startup instead of the old hard-coded Batch startup. Retain each
row's tool/session/metadata/seeds/actions. A `response` Boolean appears only for
ordinary request/notification framing used by the retained adapters; it does
not specify success, error, content or wire.

`requests(modern)` supplies compatible `(name, wire, response)` tuples for the
ordinary real stdio driver. Setup must create **both** files from
`fixture_actions(fixture)`; old Batch setup created only target. Capture one real
stdio session and all wire/filesystem evidence. No successful View body is
called because the current reference's View adapter is refusal-only.

The old observation module's `trace_frames` bound `slot < 56` is not an admission
rule for the 118-image candidate. Bind the complete new graph/source/packed
member manifest and update that mechanical bound explicitly. Do not rename an
old manifest's image count or reuse its graph PASS.

## Protocol and EOF collection

Protocol and EOF scenarios require real stdio, never private selector 34. They
cannot use the old Boolean `response_count` driver. Their count is null: an SDK
model input can be rejected, discarded or close the session, and none of those
outcomes is authored here.

For each protocol scenario, create a fresh owned process/fixture:

1. Send initial messages, then the anchor; collect through its actual input ID
   or observed EOF.
2. Write trial and recovery. Retain **every** actual line through the recovery's
   input ID or EOF, including any anonymous error. Do not collect one assumed reply.
3. Send the barrier; retain all actual lines through its input ID or EOF. The
   barrier may carry an SDK success or error; no result is synthesized.
4. Close stdin and retain remaining output, filesystem and process result. An
   early close/timeout remains evidence and never silently drops a case.

Metadata/ID trials use `from_path: []`, a non-String input for the actual String
field, so those dimensions do not introduce two valid file-edit calls in
flight. Other SDK-shape trials also lack a complete valid extract object. Only
the observed anchor and ordinary recovery are file-edit inputs. Cancellation
notifications refer to the completed anchor or an unissued ID; active-request
cancellation is outside this domain.

For each EOF scenario, observe its anchor first, write the exact tail, half-close
stdin and retain all remaining output and exit state. Do not add a newline,
pre-parse the tail, assume discard/result, or emulate AsyncRwTransport through a
private selector. The reference must expose actual SDK half-close/drain behavior.

Budgets remain **60 seconds per exchange, 180 seconds per process/lane, 15 minutes
per CI job**. Fresh-scenario grouping does not authorize a larger job budget.
All native/original/public/async qualifications remain false until real capture
and full graph/wire/filesystem/readonly-reader comparison complete.

## Source-only commands

Generate input JSON, without fixture writes or child processes:

```sh
python3 extract_public_inputs.py --fixture /ABSOLUTE/OWNED/FIXTURE --domain typed-modern
```

Verify all recorded source/input manifests without changing them:

```sh
python3 check_inputs.py --baseline-root /tmp/extract-public-6780-resume
```

`DOMAIN.json` pins every complete row/scenario and the canonical `/FIXTURE`
input object. Large integer tokens use Python integers or raw JSON bytes; never
round-trip composition/source manifests through JavaScript JSON numbers. Runtime
fixture paths remain explicit captured inputs.
