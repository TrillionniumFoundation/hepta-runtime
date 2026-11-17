# Binary read process-orphan successor

This build contains three runtime HIA images: read67, codec, stat. Only read f20 is changed; all other 66 functions retain their exact IR. The author regenerates the old f20 from its exact symbolic source before admitting the successor.

## Trusted exported interface

`binary_read_body_create(callback, callback_context, shared_process_pool)` now requires the caller's one process-wide HPORP001 pool in the third register (rdx). It validates nonzero page alignment, magic, size and creator PID. All contexts in the graph must receive the same pool. Existing callers with only two arguments are not compatible and must be explicitly rebound. Create does not create or destroy a pool.

`binary_read_body_invoke(ctx, HBRDQ001, length)`, `binary_read_body_invoke_at(ctx, borrowed_parent_fd, HBRDFD01, length)`, release and destroy retain their previous contracts. FDs are Linux nonnegative integers 0..2147483647. The borrowed parent is neither duplicated nor closed. Context+376 stores the shared pool and +400 counts successful orphan transfers. Earlier fields and the eight operable owned slots remain unchanged.

## ORPHAN_OWNED

The exact HBRDS001 kind1/op4 request is a 64-byte header: magic at0, kind1 at8, request sequence16, operation4 at24, actual owned FD32, zero words40/48/56. Only an FD actually opened by this context and still in its owned ledger is accepted. Borrowed and unowned tokens, including UINT64_MAX, are refused.

The bridge calls the unmodified c811 `hia_process_orphans_append(pool,fd,context,generation)`. Only successful append removes the owned slot, decrements operable count and increments the transfer count. It performs no close or dup. The normal HBRDQ001 resume returns raw result0 and zero payload. Resource failure retains the operable token and returns the private resource failure; resource exhaustion equivalence is not claimed by this build.

The new HIA phase34 issues that request after the first regular fstat non-EINTR error. Phase35 requires the exact empty success ACK, clears its file token, and continues the original failure cleanup. The original exception fields remain unchanged. Later fstat failures, nonregular/private validation failures and ordinary success retain their previous close order. Release, context destroy and ordinary fixture cleanup never destroy the pool or close its records. Whole OS process exit reclaims those FDs.

## Fixed private fixture

The existing HBRDFQ01/HBRDFR01 commands1..13 remain. Parent slots now store FD+1 to represent actual FD0. All observed and unobserved contexts receive the one pool created at startup.

Additional commands, with no payload:14 complete HOPSN001 pool plus all record pages;15 arm actual kernel EIO at first regular fstat phase25;16 arm EIO at second fstat phase29;17 move only the control pipe away from FD0;18 refuse an unowned token;19 refuse the held borrowed parent;20 reject pool use in an actual fork PID;21 close the fixture parent but retain its numeric slot;22 arm a fixed pre-exit EOF witness;23 arm EIO at final fstat phase39/49;24 reject null-pool construction;25 reject the empty-slot sentinel as an owned FD.

Fault arming does not provide fake syscall results. The observer installs the exact Linux seccomp filter at the designated real fstat boundary, after the fixed external ACK, then the original syscall executes and gets EIO from the kernel. The filter remains installed until process exit. Observer-disabled fault execution is outside this fixture domain.

EOF witness emits HBRDEOF1 with pool count/pages after real release/destroy/parent cleanup and before process exit, then waits for the usual zero ACK. The harness can inspect actual /proc FD custody at that live boundary. This is an observer-only fixture capability, not a public command.

This checkpoint is build-only. Original application comparisons, physical fault effects and public integration require separate qualification.
