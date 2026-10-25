# Independent review: x230 custody slice r01

## Result and evidence checked

The single x230 run supports the intended narrow custody observation. Its native process status records `succeeded`, exit zero, complete output, no timeout or cancellation, no truncated logs, and no log errors. The fixed script records all fourteen declared checks as boolean true, both original children reaped, no main error, and no cleanup error. The controller exited with `-9`; the writer exited with zero. The exact report SHA256 is `c89a057498b287d4a806e0b127259dbfa66091313404f0a7ff92704c343ed04f`.

This review did not execute the harness, open a remote connection, read real `/proc` state, or modify the frozen source. It verified the local source, README and static-check receipt against their frozen manifest, including byte counts, SHA256 and Git blob hashes. The script is exactly 22,991 bytes with SHA256 `5a94feef090e251937e99b77ee8854e046f6ce485f558c7a946161a30600b667`. Its before/after hashes and the saved plan agree. The original preparation-era README and manifest remain unchanged; this separate review adds execution facts.

The returned plan and complete seven-line event stream match the report's original-byte receipts. Event sequences are exactly zero through six, with finite nondecreasing timestamps and the expected phase order: owner ready, controller request, both original children ready, controller SIGKILL sent, control EOF with the original writer still live, original writer reaped, and observations complete with the socket retained. This supports the required ordering; it is not a performance benchmark.

All thirteen artifact receipt names are present exactly once. The four child log receipts each bind zero bytes and the SHA256 of an empty file; root additionally reported independent reads of those four remote files. This reviewer did not reopen those logs. Seven private identity artifacts are correctly marked; none was downloaded into the local public-evidence directory. In particular, the before/after socket identity artifacts have equal nonzero lengths and identical hashes. Their raw identity fields were not independently reopened by this reviewer. The public record is therefore a source-bound execution assertion and digest comparison, not an independent reconstruction of private process identities.

## What this run establishes

The pre-existing owner was the original parent of both fixed children. It retained their original `Popen` objects before subsequent identity/publication operations, obtained original pidfds before polling or reaping, and retained the fixture root descriptor. It verified the fixed writer's process identity and socket peer before allowing the controller to wait. The only explicit SIGKILL targeted the original controller through its pidfd.

The live writer did not keep the controller channel open: EOF was observed while that same writer still satisfied the live-identity checks. Only after EOF did the owner record its local frozen state and signal the original writer through its original pidfd. The writer delivered its TERM notice, exited zero, and was reaped. The known socket remained present with the same recorded stamp. There was no deletion, historical-root scan, SSH invocation, or production runtime modification.

The source's final success gate also requires the exact declared check set, final original-child reaping, no recorded main/cleanup error, unchanged source, and four empty child logs. The local AST check found no deletion or numeric-PID kill calls in the owner or either fixed child. This is a review of these exact bytes, not a general security proof of arbitrary Python programs.

## Limits that must accompany publication

The owner survived and already existed before the controller client. This run did not demonstrate production controller-to-owner startup, custody transfer, owner crash/restart, a real SSH master or its descendants, or a durable recovery protocol. No parent-death signal policy was configured. The `admission_frozen` flag represents one request and one EOF transition; there was no second client, queued request, or competing admission race.

The five-second settings constrain explicit protocol and process-wait operations. They do not impose a universal deadline on filesystem access, `fsync`, process creation, or blocked kernel I/O. Ordinary error paths preserve failure and retained artifacts; their behavior was inspected statically, not exercised by this successful run.

The new socket was intentionally retained. Original writer termination is only one prerequisite for safe reclamation. This experiment does not prevent same-UID path substitution, supply atomic inode-conditional unlink, authorize adoption of an earlier instance's directory, or change the six A26 residue sockets. It makes no reboot, power-loss, or exactly-once external-effect claim.

The next production design gate is custody from process creation: a surviving owner must be the sole launcher of the real local socket writers, retain their original handles, and fence new requests on channel loss. A separate namespace authority or equally strong mutation exclusion is still needed before implementing deletion. Neither gate should be replaced by a saved PID, unlocked advisory lease, filename, elapsed time, or a successful fixed-writer run.

## Review artifacts

[The machine-readable review](INDEPENDENT_REVIEW_X230_R01.json) binds the eight locally inspected inputs and records twenty-two consistency checks and the claim limits. The actual public inputs are [report.json](evidence-x230-r01/report.json), [plan.json](evidence-x230-r01/plan.json), [events.jsonl](evidence-x230-r01/events.jsonl), and [process-status.json](evidence-x230-r01/process-status.json). Private identity files remain represented only by their original receipts.
