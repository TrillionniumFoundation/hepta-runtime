# Native v6 facade request cancellation candidate

The old stdio facade discarded cancellation notifications and blocked its input reader during native RPCs. The candidate reads bounded input independently, preserves serialized business dispatch, and forwards cancellation through a private server-generated native request ID on the same validated native session. Unknown IDs and stale IDs cannot cancel another request. Every admitted stdio ID is tombstoned for the process lifetime (4,096 IDs); initialization does not clear this protection.

Pending operations, responses and cancellation work are bounded. Only cancellation intents that have never been submitted may be scheduled again; transmitted or uncertain intents and business writes are never automatically replayed. Existing-session replacement is refused while another request is active. Missing native session identity fails closed. Strict UTF-8/JSON validation refuses malformed IDs or deeply nested input without echoing unsafe IDs or disabling later requests.

Actual stdin/stdout/stderr file descriptors use nonblocking reads/writes and deadlines. Unread stdout and unread trace stderr caused real interpreter-exit deadlocks in earlier revisions; both reproductions are preserved and the final regression covers them. EOF has a shared three-second shutdown deadline. Generic non-file-descriptor fixture behavior does not prove process exit. The cancellation HTTP notification also has a two-second watchdog.

The final source passed 57 facade regressions. Actual optimized-native discovery/list/read-only invocation through the facade passed. Sequential acceptance on main, pocket4, rog, mac, x230 and ai395 passed 30 checks: an unknown cancellation leaves the active native wait completed; the correct request cancellation reaches native context and produces unknown dispatch metadata; the one original durable job still completes with exactly once output and the same job ID; ordinary health calls work afterwards. Every owned job reached a confirmed terminal state and every owned fixture was removed.

These are native/private-facade receipts, not genuine ChatGPT-origin calls. Cancellation means request intent, not job termination, business rollback or response-delivery proof. The facade's backend session does not establish authenticated ChatGPT caller isolation, secure reconnect or process/job caller ownership. Installed runtime/app and Desktop Commander remain unchanged; full_dc_replacement_qualified is false.

Adapter SHA256: b35313888a70a90dc72be44dc45d3f20be45337d7c2353556a382564299d649a.
Optimized native SHA256: a2eb8e7480260a9208e6fe509917b3e3b7d4ae0848e5aeedf4b048ce8c832cfa.
Core source fingerprint: c3fe01a408765ac2322ca50658ceae881dd138eb69675fa69b07bf9b6b78d803.

See docs/qualification/dc-functional-v6-facade-cancel-candidate-20261013.json and its evidence directory for exact source/log hashes. The first real-main attempt was refused before business dispatch because required authorization flags were missing from the disposable configuration. The flags were corrected only in that fixture. The trace-deadlock reproduction preserved the child stderr tail emitted by its original harness; full child stderr was not available and is not claimed.

Controlled installed activation, genuine new-tool ChatGPT calls, whole request/job audit, caller isolation and reconnect/resume, production failure/recovery/rollback, real business workflows and vendor retirement decisions remain separate open work. Desktop Commander stays available until all replacement gates pass; a risk-bearing DC-off drill additionally requires explicit user authorization and independent rescue with rollback. PR #3 remains Draft.
