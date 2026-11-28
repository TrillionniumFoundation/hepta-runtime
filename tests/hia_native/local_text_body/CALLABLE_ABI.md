# Local text body callable candidate

Source: `generated-v3/local_text_body_callable.S`, SHA256
`5120f566fe8e4ace6c441d2dd110188663cb29bcc28af26a759b44a6f86b15b6`.
Actual assembly, twelve-image HIA fixture packing, the unchanged 68-session /
129-operation corpus on both implementations, and 25 native capability groups
passed. The final fixture ELF is 2,304,951 bytes, SHA256
`3a10f516263bc13ad78f931690fdde6c28d6aa8e83c7f2815b66956fb00d016e`.
The build and complete observations are retained on ai395 under
`/home/qq/hia-text-body-callable-6780-v2`. This is finite ordinary Local body
qualification, not a public TextEditor or asynchronous-I/O cancellation claim.

SysV exports return zero-extended u32: `local_text_body_run(ctx, frame, bytes)`,
`local_text_body_resume(ctx)`, `local_text_body_cancel_wait(ctx)`, and
`local_text_body_release(ctx)`. Input remains HLTBRQ01 / output HLTBRP01;
the unsafe original input guard remains distinct HLTBGR01.

## Context

Exactly 192 bytes, little-endian u64 fields. Capability pointers are trusted
native host bindings; public request bytes cannot choose them. Fields 112..184
must start zero. All bound capabilities stay live and unchanged until release;
only the designated shared resource callback may relocate their arenas.

| Offset | Field |
| --- | --- |
| 0, 8 | HLTBCI01, 192 |
| 16 | Twelve native entry pointers |
| 24, 32 | Current request cache callback, opaque capability |
| 40, 48 | Current request hint callback, opaque capability |
| 56 | Process-shared lock-state slot record |
| 64 | Process-shared history slot record |
| 72, 80 | Shared arena growth callback, opaque capability |
| 88 | Actual parent statx byte pointer, value 0..2 |
| 96, 104 | Actual AT_SECURE 0/1, reserved zero |
| 112, 120 | Borrowed result pointer, complete length |
| 128 | Last u32 return code stored as u64 |
| 136, 144 | Completion published, capabilities drained |
| 152, 160 | Retained private control, private diagnostic |
| 168, 176, 184 | Reserved zeros |

The immutable image order is: body, local_read (metadata extension a4eacfc…),
file_lock_key, file_lock_state, editable_content, text_replace_match, history,
atomic_write, view_cache, text_replace_render, shell_capture_file (unlink),
view_error. All full identities are in ai395
`/home/qq/hia-text-body-callable-6780-v2/build-result.json`.
Members 0 and 1 were freshly compiled for a separate metadata namespace:
body source `ac7c2feece9de07129b14434aa2399c3767fa1ef2211eeca11feaead3b34ce49`,
read source `a4eacfcdae04233097a2d37ae15447b2e6e99dd5325e98b409b4404896786df0`.
The other ten images remain byte-exact from graph v5. Metadata uses HFLRMQ01
operation 3; HFLRIO01 retains operations 1 and 2 and rejects reserved 3.
384 paired complete-buffer legacy cases, 15 namespace refusals, and 21
metadata projection cases passed on the final read image.

## Shared owners and callbacks

Each shared 64-byte slot contains entry@0, workspace@8/capacity@16,
output@24/capacity@32, last-code@40, zero@48/56. Both actual owners must already
be initialized. The host serializes shared-owner invocations. Capacities start
at least 4096, in 4096-byte multiples; current carrier maxima are 256 MiB work
and 128 MiB output. Release never frees these slots or arenas. Complete state
observation uses their actual workspace pointers/capacities.
Initialize the lock owner with `HRFLOCK1` plus 56 zero bytes and the history
owner with `HHISTQ01` plus 56 zero bytes. Both return 64. The per-session
ViewCache is supplied only through the current request's callback; it is not
owned or initialized by this callable.

Cache and hint callbacks use the same signature as Create:
`u32 callback(opaque, request_ptr, request_len, OutSpan *result)`, where OutSpan
is two u64 values (pointer, length). They return 32 and a full borrowed 32-byte
response, valid until the next callback. Cache receives HVCACH01 op7 note_write
or op3 forget, with original selector1/2, and returns HVCAR001 plus24 zeros.
Hint input is HLTBHQ01, selector@8, UTF-8 size@16, zero@24, text@32; response
is HLTBHP01 plus24 zeros. The HIA body owns all history/cache/hint ordering.

`u32 grow(opaque, owner_index, needed_work, needed_output)` admits only index3
or6. Return0 means that exact shared record now has adequate capacities and
the complete old workspace survived relocation. It performs no owner call.
The bridge retries only the same resource refusal. It does not bypass the
current Scope/Lease input-window contract.

## Lifetime and scheduling

Run copies its input and retains result bytes until release. Normal completion
has drained all synchronous effects and its lock lease. WAIT=0xffffffdf leaves
completion/drain zero and exposes the existing HLTBWT01. Resume sends its
matching private wake frame. `cancel_wait` is admitted only at that returned
lock WAIT, with no I/O in flight and no held guard; it drops the lease through
the real lock owner and returns cancellation0xfffffff7.

Release returns16 until completed and drained. It then frees only private
mappings and clears result/control pointers. Infrastructure failure uses a
private code and explicit descriptor/lease cleanup; uncertain cleanup keeps
drain false. None of this asserts target Tokio cancellation between I/O awaits,
cross-thread scheduling, or public TextEditor parity. Those remain open.

The 25 native capability groups include three genuine repeated lock-Pending
resumptions, cancellation/drop of that waiter, predecessor release followed
by completion, busy-release refusal, malformed bindings/frames, callback
failure after atomic write, and shared-history allocator refusal or relocation.
All original 68 cases, 129 operations, and 60-second per-process / 180-second
outer deadlines remain unchanged. Native safety guards for known unsafe
original input boundaries retain HLTBGR01 and are not labelled original
success equivalence. Older attempted sources and failures are kept outside
the final implementation rather than being rewritten as successful runs.
