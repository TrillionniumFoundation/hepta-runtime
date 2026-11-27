# fb42 original CI and one same-head diagnostic retry

The push exact-head and PR prospective-merge lanes passed both complete test
configurations and their selected release gates. The original PR exact-head
lane failed one actual SSH initialization fixture before its injected agent
fault. Its complete log remains here alongside both complete successful logs.
Existing skips are reported separately and are never counted as passes.

The original run attempt, exact public ref, branch metadata, six addressed
review threads, public PR body and one official job-rerun response are retained.
The retry was requested only after the other two lanes finished. No source,
fixture, SSH guard, execution budget or expected result changed. This directory
records the initial failure and the retry's real in-progress state; it does not
assert that the retry passed or authorize repeated retries.

The data describe source fb42bd643458e3e1435a0584ba4690ea98071838. They are
retained on the independent native-common integration branch so preserving the
receipt does not change or cancel that public head's live matrix. The existing
old common-candidate catalog failure remains HOLD. Public activation, native
whole-source qualification and old-stack removal are not claimed.
