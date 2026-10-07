# Independent observation and cooperative live stream ownership

> **Installed status (2026-10-07):** the six native `stream_handoff_*` tools and persistent broker described below are installed. `deploy/dc_handoff_owner.py` has also been exercised as an actual Desktop Commander-launched owner against that installed broker: finalized stdout/stderr histories became the exact native archive prefix, zero userspace read-ahead was unaccounted, the same application continued without checkpoint/restart, and the broker survived an MCP service restart. See `docs/qualification/operator-dc-native-handoff-20261007.json`. The earlier “candidate” wording below is retained as development history. Retroactive adoption of arbitrary pre-existing DC sessions that were not launched through a cooperating owner remains unsupported.

This stage addresses the outstanding hardware/maintenance/resource-handoff work without changing Desktop Commander, the installed runtime, host permissions or the prior CRIU contract. It does not register new MCP tools or claim that general process-tree snapshot capture is implemented.

## Independent peer observation is not power control

`deploy/independent_observer.py` is a finite, normal-user observer on a different trusted SSH host. It retains a private report on that peer after its initiating SSH connection has ended. It verifies challenge-bound responses and the expected controller boot identity from an explicitly owned test endpoint and separately observes the real controller's SSH banner. It cannot authenticate to the controller, issue a command, send a wake packet or operate a power supply.

`tests/independent_observer_acceptance.py` exercises a single ephemeral test listener through up/down/up, while leaving the actual SSH and MCP/DC services running. A successful result proves that the independent peer process and its saved observation survive the launch channel ending, and that the observer distinguishes endpoint failure/recovery. It does not prove actual controller reboot, NIC wake from a powered-off state or mechanical AC/battery/standby-power removal. The observer terminates after its bounded sample count; this is not a hidden recurring monitor.

A real power qualification still needs a verified separately powered actuator, exact target/outlet binding, power-state readback, and a recoverable business-state window. An absent management device node or an unsuccessful plugin search does not prove no hardware exists; it means a usable connected route has not been established.

## Read-only maintenance and resource evidence

`deploy/maintenance_inventory.py` reports active business-like processes, interactive applications, stateful services and container visibility. No absence-of-name heuristic produces `safe_reboot_proven=true`: application durability and restart contracts require actual evidence. It never executes a power action, takes a process checkpoint, grants rights, reads process memory or returns file contents.

With `--pid`, the inventory lists a bounded same-login process tree, fd roles/object identities, and matching descriptor owners outside that tree. It rechecks process start identities and selected descriptor bindings. Root-owned/inaccessible or racing objects remain explicit unknowns. A disappearing descriptor does not erase other descriptors already observed from that process; a regression test and real fixture cover this case. Incomplete visibility never becomes proof that no other owner exists. The report cannot itself authorize capture, adopt unknown resources or relax the native snapshot admission rules.

## A distinct, nonprivileged route for live external streams

`deploy/stream_handoff.py` implements a small Linux same-login cooperative pipe transfer using `SCM_RIGHTS` over a private Unix-domain socket. The old I/O owner voluntarily sends descriptors it already holds after explicitly acknowledging that its own input/output activity is quiesced. The receiver checks kernel peer credentials, source identity, pipe object/access mode, application identity and the corresponding actual application stdio. Received handles use close-on-exec. A private create-only receipt is synced before acknowledgement; stale IDs and repeated receipt publication fail closed.

The application and its child continue running. The kernel transfers references to the same open pipe objects, rather than reopening named files, copying process memory, restoring a snapshot or changing the application PIDs. Buffered bytes still in those pipe objects remain available. The caller must handle its own userspace read-ahead buffers and establish a quiescent boundary. The implementation does not infer exclusive ownership from fd numbers or silently stop a competing reader.

A missing acknowledgement is ambiguous. The source must not blindly replay a transfer or resume I/O without reconciling the receiver. The helper does not promise persistent handles after the receiver crashes, durable memory after power loss, automatic supervisor adoption or cross-host migration. At that historical stage it was only a library/fixture. The current installed runtime now supplies the native receiver, and the handoff-aware DC owner exports exact live child pipes plus finalized history. This still does not retrofit descriptor export into arbitrary pre-existing DC sessions that were not launched through the cooperating owner.

## Executed qualification

The real fixture contains an application and a child worker, each with random in-memory state and no save/reload/checkpoint interface. The old launcher consumes state 17, sends an additional 5, and deliberately leaves the resulting output unread in the original kernel pipe. It transfers its stdin/stdout handles and exits normally. The receiver reads the queued state 22 and submits only a new 7, receiving state 29. Both PIDs, start identities, random memory hashes and child relationship remain unchanged. No application stop/resume, root operation or old input replay occurs.

The inventory also identifies the old launcher as an external pipe owner before this transfer, without authorizing any process mutation. The failed first combined fixture is retained: a racing self-inspection fd initially hid the launcher's otherwise-known descriptors. That inventory defect was fixed; assertions were not removed.

The unit suites cover peer/identity/access checks, missing quiescence consent, non-pipe rejection, private endpoint creation, existing receipts, partial `/proc` visibility, process/fd reuse, authenticated observer responses and malformed/stale observations. The independent peer test uses existing SSH trust but no controller credentials. Neither test is a substitute for a real physical maintenance event.

## Current authorization boundary

If the connected execution channel forbids privileged or lifecycle commands, these helpers do not conceal those commands inside scripts, modify the blocked-command list or route them through the existing native sudo implementation. The previously blocked general CRIU tree module is not reconstructed here. Only explicitly owned ordinary-user test pipes and test listeners are changed; live business services and DC stay untouched.

## Primary references

- Linux Unix-domain sockets, peer credentials and descriptor passing: https://www.man7.org/linux/man-pages/man7/unix.7.html
- Open file descriptions and shared file offsets/status: https://www.man7.org/linux/man-pages/man2/open.2.html
- CRIU's different explicit resource-remapping contract and its limits: https://www.criu.org/Inheriting_FDs_on_restore
- systemd inhibitor locks and why absence of an inhibitor is not application-state durability: https://systemd.io/INHIBITOR_LOCKS/

## Native runtime receiver (historical candidate section; now installed)

The next candidate integrates the cooperative stream owner into the compiled runtime as six controller-local tools: `stream_handoff_prepare`, `stream_handoff_status`, `stream_handoff_read`, `stream_handoff_write`, `stream_handoff_close`, and `stream_handoff_list`. `prepare` binds an idempotency key to exact same-login application identities and starts a separate user-systemd broker. The broker, not the MCP controller process, receives the cooperating owner's pipe descriptors. Restarting or SIGKILLing the MCP controller therefore does not close already accepted application pipes.

The native receiver archives stdout/stderr before returning bounded base64 pages with byte offsets and hashes. Input requires a request ID and records only length/hash/status, not raw bytes; same-ID/same-bytes returns its receipt and changed bytes are rejected. A partial/uncertain write is never silently replayed. `close` closes the accepted input writer only and does not signal the application. Completed output remains readable after the broker exits.

A real candidate test uses an application plus child worker with independent random memory and no checkpoint API. Output already queued before handoff is retained. The old owner voluntarily transfers its exact three stdio pipe handles and exits. The runtime controller is then SIGKILLed while the app and broker continue; output produced during controller downtime is recovered after restarting the controller with the same state directory. Subsequent idempotent input changes the app/child state once, with both PIDs and memory hashes unchanged, and EOF produces a complete final archive.

This receiver closes only the **runtime side** of the ownership gap. The generic new-command owner wrapper attempted in this continuation was blocked by the session safety check before file creation and was not repackaged or retried. Existing Desktop Commander sessions still do not expose their already-read userspace buffers or pipe handles to this API. The separate reviewed `stream_handoff.py` helper remains the explicit cooperating-owner export protocol used by qualification. Kernel pipe bytes are covered; bytes already consumed into an old owner's private read-ahead buffer remain an application/owner boundary and are not claimed transferred by the installed protocol.

## Finalized old-owner history and DC-launch integration (now installed for cooperating launches)

The installed native broker now owns live exported pipes independently of the MCP controller. The remaining lossless old-owner boundary is bytes that the old owner has already consumed from those pipes before descriptor transfer. Kernel descriptor passing cannot reconstruct those private user-space bytes.

The current candidate resolves this only for work launched through the explicit handoff-aware owner `deploy/dc_handoff_owner.py`. That owner uses raw, unbuffered child pipes. Every child stdout/stderr byte it consumes is first appended to a private per-stream history file and only then forwarded to Desktop Commander. On handoff it requires zero unread bytes on its own raw stdin, fsyncs the histories, and transfers the same live child pipe descriptors plus read-only finalized history descriptors to the native broker. The broker SHA256-verifies and copies that finalized history as the beginning of its durable archive before it starts consuming live pipe bytes.

The acceptance fixture verifies that the pre-handoff owner history is byte-for-byte the native broker archive prefix, the child PID and random-memory hash are unchanged, no application checkpoint/restart occurs, and post-handoff input continues the same application state. A live installed-runtime restart is qualified separately while the broker owns the pipes; the application and broker remain alive while only the MCP controller service changes PID.

This is a practical zero-gap path for **new DC work intentionally launched through the wrapper**. It is not retroactive adoption of arbitrary pre-existing Desktop Commander sessions: DC's own Node.js process does not currently export already-open child descriptors or any private read-ahead buffers into this protocol. Existing business DC sessions therefore stay on DC until they complete or until DC itself gains an explicit export/quiescence hook.

History files are account-owned, read-only at transfer time, size/hash/device/inode/timestamp bound, and must be explicitly finalized. Changed history fails before broker acknowledgement. The protocol does not infer that an uncooperative reader stopped consuming a shared pipe, and ambiguous acknowledgements must be reconciled rather than replayed.
