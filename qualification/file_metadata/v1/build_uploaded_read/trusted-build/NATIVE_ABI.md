# Fixed borrowed-file metadata callable

This is a private Linux x86-64 component. The HIA owner implements the original file_metadata.py policy. The native boundary only performs the eight explicitly emitted descriptor-relative system calls and invokes the fixed HIA SHA256 codec. It never opens, duplicates, reopens or closes a borrowed source or target FD. Public host configuration and SSH transport remain separate and unqualified here.

## Entry and response ownership

file_metadata_create(callback, callback_context) returns a private context. file_metadata_invoke(context, source_fd, target_fd, packet, packet_length) accepts an exact HMDTQ001 request (see ABI.md). The source and target FD words in the external packet must be zero; the entry copies the whole packet and injects only its trusted registers. Mode1 capture uses source_fd and requires target_fd0. Mode2 summary uses an already owned snapshot and requires both register FDs0. Mode3 preserve uses both borrowed FDs.

The complete HMDSR001 final packet remains borrowed until file_metadata_release. Destruction refuses an active or borrowed-response context. The internal FD ownership ledger stays empty. Result completion, failure, release and destruction never close either parent's descriptor. The parent must keep the exact descriptors valid throughout the synchronous invocation.

## Fixed native effects

| HIA operation | Actual Linux x86-64 call |
| --- | --- |
| 1 | fstat (5), complete144-byte stat |
| 2 | flistxattr (196), requested capacity at most65536 |
| 3 | fgetxattr (193), exact NUL-terminated name and capacity at most65536 |
| 4 | fchown (93) |
| 5 | fchmod (91) |
| 6 | fremovexattr (199), exact NUL-terminated name |
| 7 | fsetxattr (190), exact name/value, flags0 |
| 8 | fsync (74) |

Read effects admit only the bound source, or the bound target in mode3. Write effects admit only the bound target in mode3. Mode2 admits no operating-system effect. HIA owns retries, order, metadata equality, budgets, sorting, hashes, structured exceptions and final formatting. The trusted image table contains exactly body and codec; no input chooses code or syscall addresses.

## Private fixture

Length-prefixed HMDTFQ01 requests use a64-byte header: operation8, context slot16 (0or1), payload length24, all remaining words zero. HMDTFR01 replies carry actual return8, payload extent16, context state24, invocation32, owned-FD bitmap40 (always0), output capacity48 and work capacity56.

Operations1invoke,2release,3destroy,4fullcontext,5fullworkspace,6fulloutput,7fullinput,8create observed and9create observer-off retain the existing complete binary carrier convention. Operation10 holds a source file;11 holds a target file;12/13 close source/target;14/15 return actual source/target fstat;16/17 actually close a file while retaining its numeric argument for a frozen bad-descriptor case. No replacement descriptor may be opened after that negative fixture step. The carrier owns these files and opens them O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK so nonregular files reach the original policy's regular-file checks.

FD3 receives complete HMDTJR01 journal spans. FD4 emits HMDTHK01 immediately before each fixed native OS request; FD5 accepts only a zero acknowledgment. This permits an independent real filesystem actor to perform a frozen mutation, then allows the actual syscall to run. It cannot replace syscall results. The callable's observer-off variant still performs all actual effects.

## Build qualification boundary

The source author was executed in CI and reproduced63 HIA functions /3848 operations. This package performs four actual HIA compilations (body, codec, linker, packer), then actual HIA link and image pack. It copies and completely reverifies the previously captured actual B3; it creates no new seed or bootstrap generations. The output is a syscall-only ELF. Application semantics are not exercised by this build gate. Original Python comparison, real filesystem mutations, borrowed-FD lifetime, physical corrupted-evidence controls and uploaded archive readers must close the later semantic gate before use as a qualified metadata implementation.
