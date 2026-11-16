# Fixed accessor performance candidate

This is an isolated engineering successor to the exact 111-image default graph
at 08406d5bf4e79795425012230a760f0f52e2adce. It is not an installation or a
complete public qualification.

The complete stage-clock capture at f42fbf202a73f5864e4153e812cdbf757b873d4a
(run 43968184917) passed, and every archived member was independently read.
It locates substantial ordinary-request time in G1 and Value. The values are
monotonic wall durations; solver response timing is not a CPU measurement.

## Source change

`author_accessors.py` accepts the two exact old SHA256 values. It removes
only proved identity operations in six fixed byte helpers and contracts
single-block access wrappers at 658 call sites. The ordered eight checked
byte accesses, wrapping addresses, first bounds trap, and partial write prefix
have a symbolic proof. An exact inverse reconstructs both complete old sources.
All function signatures and control-flow edges stay fixed. There are no new
input predicates, numeric algorithms, or skipped Value conversions.

Expected generated HIA is frozen under `expected/native/`. CI must reproduce
those full bytes, parse both revisions with the exact Hepta compiler, and
validate the source proof before compiling either owner.

## Execution and evidence

CI admits every member of the retained complete build first. It freshly
compiles the two changed leaves, strictly reuses 101 other leaves from run
43961663648, and reuses the unchanged eight-member packed worker capability.
The copied verified B3 is explicitly a reused compiler, not a new cold build.
The fixed FD4 observation adapter remains the previously frozen source.
The resulting graph is engineering-only.

For each of the three exact retained requests and each changed owner, CI
retains old/new return codes and the complete output and workspace under four
capacity/fill profiles. The pure reader reads every retained byte. This is
24 complete buffer pairs and 48 native invocations. It then performs the three
ordinary stdio sequences with the unchanged observer and full wire comparison.
Every observer process remains bounded by 60 seconds and the job by 15 minutes.
The full public domain still requires all 1394 original records under the
unchanged 180-second process and 60-second exchange limits.

`CORPUS.json`, its source-unchanged note, and the retained failure receipt
describe the original diagnostic input capture, not this candidate.
`PERFORMANCE_CHANGE.json` states the candidate's actual changed-source scope.
The old EOF observer failure, original timeout, and all earlier failures remain
separate and immutable. All global completion flags remain false.
