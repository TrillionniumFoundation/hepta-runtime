# Third full gate: preserved timing assertion failure and cancellation

This attempt is **not qualified**. Its original summary, logs and source-before inventory remain unchanged. The original durable job `1a1a19768ff-96a-6ff4` terminated as `cancelled`, exit `-15`, with complete retained output.

Formatting and both strict all-target Clippy configurations passed with explicit child launch umask `0022`. All-feature nextest ran for 2,043.273 seconds before the deliberate stop. Its verbatim result is:

```text
1452/1844 tests run: 1450 passed (4 slow), 2 failed, 39 skipped
```

One failure was the original assertion in `large_pending_view_remains_exact_while_continuous_publications_progress`: after joining a successful writer, the test required the whole 64-receipt workload and concurrent queries to finish before a single ten-second deadline. The observed test duration was 12.856 seconds. That assertion preceded the observation-consistency checks, so this record does not claim those later checks passed.

The second reported failure was `active_retention_never_erases_intents_or_refuses_archive_only_admission`, which nextest explicitly records as **SIGTERM from cancellation**, not an independent failed content assertion. Another 392 scheduled tests did not run. The no-default nextest stage did not run.

## Cancellation and source observation

The runner did not complete its final monitor shutdown/summary finalization before its owner terminated. Consequently the retained `summary.json` still has its last `running` status and `qualified: false`; it is not rewritten into a successful or complete run.

`owner-terminal.json` records the authoritative original-job terminal. A separate post-terminal read-only observation found no remaining task runner/test processes, acquired the task-exclusive target lock, and found the content inventory equal to the source-before inventory:

`745b81bb4891ba354c90b94e569d9c86ef2813200da525d0f8eb90421dbdeb73`

See `post-cancel-observation.json` and `source-after-cancel-observation.json`. This later inventory does not reconstruct the missing continuous-monitor finalization.

## Correction and final validation route

Read-only review identified that the ten-second assertion imposed an entire-workload throughput threshold, while the tested contract requires exact concurrent views and continued publication progress. The runtime query budget remains three seconds; production pending/cohort rules, FIFO admission and file/directory synchronization are unchanged.

The test-only correction watches real successful durable-completion events, retains a ten-second **no-progress** watchdog, joins the writer, and retains all 64 publications, monotonic/statistical consistency checks, final count 65, unchanged cache bytes and post-flush equivalence checks.

The final prepublication receipt is recorded separately in [rea-final-focused-20261103-r1](../rea-final-focused-20261103-r1/summary.json). Complete committed-tree suites in both feature configurations are required in #84's exact-head and prospective-merge GitHub CI. None of those later results retroactively change this failed/interrupted attempt.
