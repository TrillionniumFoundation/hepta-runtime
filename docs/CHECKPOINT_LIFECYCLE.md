# Two-phase native checkpoint lifecycle

The `process_checkpoint` contract separates restoring process memory from allowing the restored program to execute. Tool registration does not enable it on every host: the administrator must pin both an absolute CRIU executable and its SHA256 on a Linux operator host. Existing OS/sudo rights remain the authority. No new sudoers, PAM, kernel policy or remote account is installed by this API.

## Explicit states and actions

`inspect` returns a PID/UID/kernel-boot/start-tick identity and a resource admission result. `dump` requires that exact identity and a process-stop acknowledgement. It holds a pidfd, stops the identified process, inspects it again and fingerprints all supported mapped/open regular files. Only after a successful CRIU dump and private image-hash validation is the original process terminated. Failed captures resume an originally running task when possible; an originally stopped task is not silently resumed. The original owner must reap the old process before its PID can be restored.

`restore` verifies the original boot, absence of the old numeric PID, unchanged mapped/open files and private image hashes. It records intent before CRIU executes. Success returns **`restored_stopped`**, the new exact process identity and `requires_explicit_resume: true`. A restored stopped task is never reported as a running program.

`resume` is a distinct action with `acknowledge_resume: true` and the exact `expected_identity` returned by restore. It rechecks the process using a pidfd, verifies that it is stopped, durably records resume intent, sends SIGCONT only to that process, and records completion. Missing acknowledgement or stale identities do not signal anything. Confirmed repeated resume/restore requests return the recorded result, not another signal or application launch. `status` is observational and exposes actual identity/state when available. Interrupted or uncertain intent states require reconciliation; automatic lifecycle replay is not inferred from a timeout.

## Qualified resource boundary

This first native lifecycle admits one ordinary same-login, single-thread process, with supported regular files, basic null/random devices and process-internal pipes. It does not require application checkpoint/save code. It rejects child-process coordination, sockets, terminal/GPU/device resources, external pipe endpoints, deleted mapped/open files, mixed identities and incompatible resources before capture. Checkpoint and restore must occur during the same kernel boot. All pinned dependencies must still match; snapshot images do not magically snapshot an externally mutable filesystem.

Restoration can preserve random in-memory values, unread anonymous-pipe bytes, the numeric PID/UID and regular-file offsets. These assertions are tested with disposable ordinary processes, not inferred from a successful CRIU exit. They do not establish general migration of graphical applications, network peers, arbitrary DC-owned buffers or cross-host/cross-kernel compatibility. External-pipe standalone experiments remain separate from this admitted native scope.

Private root-owned snapshot/state files remain below `/var/lib/hepta-runtime-checkpoints-v2/<original-uid>/<id>`. They may contain secrets and must not be uploaded as test artifacts. Public results expose image counts and statuses, not snapshots, raw memory or dependency paths. A checkpoint identifier is immutable for its original target/pinned artifact; use a new identity only for a genuinely new authorized snapshot, not to conceal an uncertain prior restore.

## Difference from the retained earlier experiment

The earlier non-shipping experiment restored a stopped process but did not deliver the claimed automatic continuation. Its failed receipt remains historical. This implementation does not retrofit that attempt into a pass. It explicitly models the stopped restore phase, tests that the program makes no progress before authorization, rejects missing/stale continuation requests and then tests the separate identity-bound resume. Any new installed qualification must name the exact release and new acceptance receipt.

## Other boundary work

The current baseline already includes S5 shutdown/wake evidence, inode-preserving patches, protected PDFs and supported complex workbook context. None of those prove mechanical removal/restoration of AC and battery supply, a safe physical restart of a currently busy controller, arbitrary signed-content trust or full Excel/browser identity. Those limits must remain separate from successful software lifecycle tests.

An independent 1904-calendar audit found that `TEXT(serial,"yyyy-mm-dd")` was being rendered in the engine's 1900 date domain even though DATE/YEAR used the workbook domain. The reviewed correction keeps format-section conditions on the original numeric value and shifts only the selected calendar rendering; numeric and time formats are not indiscriminately offset. Tests verify the exact date, numeric formatting, conditional branch and restoration of the next 1900 workbook's engine behavior.
