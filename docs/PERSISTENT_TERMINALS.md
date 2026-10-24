# Operator archives and persistent terminals

This is the candidate implementation for the next local replacement stage. ChatGPT/cloud registration is intentionally deferred. Read the exact qualification receipt before treating a source change as installed or qualified.

## Output storage

New operator durable jobs no longer discard stdout/stderr after 16 MiB. The target-account supervisor writes the complete streams to `stdout.log` and `stderr.log`; readers still return bounded pages. Existing isolated-job retention remains unchanged. A pre-upgrade job keeps its own previously installed runner and cannot reconstruct bytes that were already dropped.

New operator PTYs use a target-account terminal owner and an append-only `output.log`, not the old 4 MiB controller ring. Read with `pty_read` byte offsets; text pages preserve UTF-8 boundaries and `raw_bytes: true` returns exact byte pages with `bytes_hex`. Responses include the target archive path and a chunk SHA256. Completed archives are not deleted automatically.

There is no promise of infinite physical storage. Check free disk space; read/write/flush errors or incomplete draining make `output_complete` false. Files remain private to the target login and its OS-authorized administrators. Terminal output may contain sensitive application data. The terminal application's echo settings still control whether input appears in output; do not put real passwords in chat, argv, environment, or durable start requests.

## Controller restart recovery

For an explicitly configured operator host, `pty_start` creates a target-owned process with a real controlling terminal. Linux uses the existing login's user-systemd manager when available; other supported cases require the administrator's existing `allow_detached_fallback` setting. A failed or uncertain systemd launch is not retried as a detached launch.

The controller writes a private session reference before invoking the target. Use an `idempotency_key` on `pty_start`; the same key and request return the same identity. Reusing a key with different start parameters is rejected. An ambiguous launch must be reconciled with that identity, not retried with a new key.

Normal controller shutdown and controller SIGKILL do not close persistent operator terminals. After restarting the controller against the same state directory and unchanged host binding, use `pty_list` and the original session ID to read or write the same terminal. Local listing is bounded and returns `inspect_with_pty_read` for persisted records; `pty_read` retrieves live target status. `after_session_id` and `limit` page persistent records. Existing isolated PTYs remain controller-scoped.

For input, an optional `request_id` deduplicates retries at the still-running terminal owner. Reusing it with different bytes is rejected. The owner records an input digest and byte-count receipt in memory, not plaintext input in metadata. Check `bytes_written` and `complete`: a partial write is not permission to resend the entire payload under a different key. Do not retry input blindly after an unknown transport result without an idempotency key.

`pty_close` requests termination of this terminal's owned process group and preserves its archive. The account's actual OS permissions remain authoritative; a child that changes UID or deliberately escapes the process group can require separately authorized cleanup. The runtime does not grant new sudo rights or claim universal containment.

## Target reboot and loss

A controller restart is not a target reboot. Existing programs cannot continue across an ordinary target reboot. Target boot identities are checked; a prior running session returns `lost` with a reboot/unreachable-owner reason rather than silently launching the application again. Previously archived bytes remain readable while the target filesystem is available. A simulated boot-identity regression is not a physical reboot test.

## Existing Desktop Commander sessions

A live DC child, input pipe, in-memory buffer and terminal cannot be converted into a new runtime session merely by copying its PID. Never stop DC just to make a cutover dashboard green. Preserve the old channel for existing sessions; route newly started work to qualified runtime tools. End or checkpoint each old application through its supported workflow, then verify no required sessions remain before retiring DC. Sessions intentionally started inside an independently persistent terminal multiplexer may be reattached through that application's own API, but this does not migrate arbitrary DC sessions.

## Qualification

`python3 tests/terminal_host_tests.py` exercises real disposable local PTYs, complete archives above 4 MiB, client exit/reconnect, launch/input deduplication, UTF-8 and binary cursors, synthetic password-style echo suppression, and simulated boot-identity loss. It does not authenticate through the host's sudo/PAM password policy.

`python3 tests/lifecycle_acceptance.py --binary <release> --ssh-target <existing-alias> --out <report.json>` uses a separate temporary authenticated MCP controller and disposable target jobs. It verifies full archives above 16 MiB and 4 MiB, same-PID PTY recovery after graceful controller exit and SIGKILL, once-only input, and existing noninteractive sudo. It neither reboots a business host nor changes its sudoers/PAM.

Document/image interfaces, staged binary prototypes, actual password prompting, physical target reboots and native DC live-session migration must be tracked separately from these tests. Native binary prototype files are not a deployed API unless registered, tested and installed.
