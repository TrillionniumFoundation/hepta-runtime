# CDP reference process cleanup fix

Base: `737acf6f901e46c57b0b4374e323e0d1132e0d49`.
Worktree: `/workspace/scratch/d72683e5e62a/cdp-cleanup-fix`.
The three source files remain unstaged and uncommitted. No remote operation was performed by this patch task.

## Scope and behavior

The previous shell trap waited only for the original Chrome and HTTP process IDs. A remaining Chrome descendant could still write the temporary profile while `rm -rf` was running. Root's independent artifact review found the original CDP observation and all five assertions successful; the hosted run failed during profile removal.

The workflow now starts a dedicated Linux Python owner. HTTP, Chrome, and the unchanged probe each receive a separate session. The owner acts as a child subreaper so orphaned descendants, including those that created another session, remain in its custody. It retains each original `Popen` object and observes exits with `waitid(..., WNOWAIT)` until final cleanup; this keeps group leader identities from being reused before group signals finish.

Cleanup sends TERM only to these private groups and actual direct or adopted children, waits at most three seconds, then uses KILL if needed and waits at most three more seconds. A stable child snapshot and non-reaping exit checks distinguish fully exited children from a zombie thread-group leader that still has writing threads. The final reap loop has a separate three-second bound; the owner must reap all children before a single profile removal. It does not use process-name matching, global Chrome termination, deletion retries, or ignored removal failures.

An existing profile is refused and retained. A nonzero probe result takes priority over cleanup failures; a lifecycle or cleanup failure after a successful probe produces a nonzero final result. SIGINT/SIGTERM initiate the same cleanup and preserve the signal exit status. `process-cleanup.json`, included in the existing evidence artifact, records only this operation's PID/session identities, TERM/KILL usage, reaped and remaining live children, profile removal, and separate probe, lifecycle, cleanup, and final results. It does not collect process arguments or environments.

## Files changed

- `.github/workflows/rea-browser-real.yml`: replace the shell trap with the owner, retain the probe's CDP JavaScript and five assertions byte for byte, add helper/test path filters, and run the dedicated lifecycle regression step.
- `.github/scripts/rea_browser_session.py`: the CI-only owner and cleanup receipt.
- `.github/scripts/test_rea_browser_session.py`: eight Linux process regressions.

No Rust, runtime, HIA, dependency lock, frozen fixture, or other workflow source changed.

## Actual validation

`lifecycle-fixtures.json` and `lifecycle-fixtures.log` record eight passing cases, exit 0, in approximately two seconds. These use real child processes, signals, reaping, profile writes, and a separate unrelated sentinel process:

1. The original parent exits before its session-escaping child, which continues writing and ignores TERM.
2. A cooperative orphan exits on TERM without KILL.
3. One stale child snapshot represents the late-adoption sampling window; the real surviving orphan is discovered, signaled, and reaped.
4. Probe exit 37 remains 37 after successful cleanup.
5. Probe exit 37 remains 37 when profile removal also fails.
6. Profile removal failure turns probe success into exit 1.
7. Cancellation cleans descendants and returns 143.
8. The main native thread calls `pthread_exit`; `/proc` reports its leader as Z while another thread still writes. Cleanup still kills and reaps the complete process.

Every case checks that the unrelated sibling sentinel remains alive and continues writing. Removal failures are intentionally injected; they are surfaced, not retried or ignored. The late-adoption test injects one stale observation; its processes and teardown remain real.

The local Linux environment omits `/proc/self/task/<pid>/children`. The helper therefore uses its explicit fallback: read numeric procfs stat entries, retain only `PPID == owner`, and never inspect arguments or environments. The ordinary children-list path is retained for hosted Ubuntu. Final hosted Chrome validation remains the publisher's next step; these local results do not claim that run has completed.

`source-and-shell-checks.json` records exact equality of the original JavaScript slice and five-assertion slice, successful `bash -n` for both workflow shell and generated probe, Python syntax checks, path filters, and a reversible, clean patch. `cdp-cleanup-fix.patch` is the complete three-file patch, including the two new files.

Earlier observations are retained in the `pre-*` files. The first two development attempts stopped before starting owned services because the local procfs children entry was absent; the diagnostic and fallback then resolved that concrete environment difference. Later retained runs document the additional receipt, lifecycle-error, and thread-group fixes.

## Practical limit

The owner requires Linux procfs and child-subreaper support. An uncatchable kill of the owner, runner loss, or a kernel-uninterruptible child cannot be repaired by a userspace cleanup handler. If bounded teardown or reaping fails, the helper reports failure and retains the profile. It never labels that state as completed cleanup.
