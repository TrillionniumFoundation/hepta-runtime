# JavaScript MCP request cancellation

The original v6 parser transport did not receive rmcp's request cancellation token. The exact v6 runtime was tested through actual stdio MCP, with its owned parser pinned by PID, PPID, argv, start identity and pidfd. SIGSTOP prevented natural completion. After notifications/cancelled(requestId=3), the same stopped child was still present under the live original owner after the unchanged five-second observation window.

The negative receipt and all 34 original payload files remain under negative-v6; its manifest binds those historical bytes. Finally cleanup killed only that owned pidfd and confirmed reaping before closing the parent. That manual cleanup was not counted as cancellation success.

The candidate patch passes the request token into source admission and the isolated worker. Running-worker cancellation explicitly kills and waits for the original Child before releasing its slot. A bounded file read already in progress completes under the retained permit before returning cancellation. The absolute 20-second worker deadline and all byte/node budgets remain in force.

The same unchanged Python harness is installed as tests/rea_javascript_cancellation_external.py. Actual acceptance on the final combined release is recorded separately; applying this patch alone is not qualification. Arbitrary future-drop and runtime-exit cleanup are outside the explicit synchronous-reap claim.
