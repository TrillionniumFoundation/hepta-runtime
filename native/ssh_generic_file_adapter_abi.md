# Default generic SSH owner for native file calls

This profile embeds the five unchanged HIA policies and seven retained mechanical
owner sources qualified by the complete original direct-SSH 19-method gate in
commit 0037b4695a925b6c8540c15aa41099c4ce56a5a7. It connects the default native MCP
process to that process-owned graph. A sixth HIA leaf performs only the private
file-plan and result framing. The private owner constructor is retained with its
own explicit source identity.

## Runtime lifetime

One installed runtime hub retains one generic owner across requests and sessions.
The event loop is the only writer of the outer call list. Generic workers and the
persistent shutdown join are independent kernel threads. Dropping a caller marks
that exact generic request cancelled; it does not dispose of the owner, child,
pipes, request record, or retained final-entry guard.

The extension wraps three complete retained terminal-notification methods with
an eventfd wake after their original publication. Polling still requires actual
HIA terminal state and kernel completion; eventfd readiness is not a completion
receipt. The final destroy operation requires both owner and join clear-TID
words to be zero, the original successful join result, empty queue/drain/
quarantine, no outstanding HIA deferral or journal loan, and equal allocated and
freed request counts. Failed or unknown completion retains custody.

The default observer is null. Final destruction has the explicit private
precondition that the event-loop owner has stopped submissions and has exclusive
outer API ownership. This profile does not advertise concurrent outer
cancel/release/destroy methods.

## Closed private frames

Every scalar word below is little-endian u64. Public tool parameters cannot
supply image pointers, descriptors, child PIDs, final-entry callbacks, generation
numbers or these private frames.

| Frame | Extent | Meaning |
| --- | --- | --- |
| HSGWK001 | 64 bytes | Version 1, actual kernel envp, admitted sealed OpenSSH descriptor, nonzero generation, three zero words |
| HSGCMD01 | 64-byte header plus exact plan and environment records | Version, sealed descriptor, plan length, environment record count and byte length, two zero words |
| HSGCMR01 | 64-byte header plus HSDCMD01 command and stdin | Exact complete command length, stdin length, admitted operation and request identity |
| HSGRSP01 | 128-byte header plus stdout and stderr | Actual generic result, identity, raw status, cleanup/commit/spawn/reap observations and complete returned streams |
| HSSHRR01 | 128-byte header plus complete returned streams | Existing native file transport result consumed by the unchanged downstream file gateway |

The HIA framing leaf accepts only the actual HFBSHP03 file profile, operation 1
or 2, pool flag zero, 30,000 ms deadline, two 8 MiB stream bounds, exactly 12 argv
members, exact payload extents, the native-entry selector and all required zero
words. It compares the first ten argv members byte for byte:

    /usr/bin/ssh -T -o BatchMode=yes -o ConnectTimeout=8
    -o StrictHostKeyChecking=yes -o ForwardAgent=no

The final two arguments are the installed configuration's captured SSH target
and quoted native file entry. Environment records come from the actual process
kernel envp. A private sealed-descriptor executable path is generated in HIA;
public JSON supplies neither it nor a replacement environment.

The installer retains the previous complete OpenSSH capture method. The actual
ordinary installed executable is captured from its held inode, checked before
and after, copied into a memfd and sealed with all four seals. The capability
duplicate stays with the runtime root until completed destruction. The five
original policies, framing image, static linker and image packer are source and
image pinned by the current build receipt.

## EOF and cancellation

The original current SDK has two different clocks. Receive EOF starts its
unchanged five-second response drain. Actual stdout closure is the observable
transport-close boundary. Only then are retained handler futures destroyed;
the independent process owner performs cancellation and reaping afterwards.

The normal two-request gate keeps its original 30-second reply, five-second
completed shutdown and three-second adopted-child observation limits. A new
pending-request gate separately observes the original SDK drain and then
applies the same five-second completed-shutdown check after real stdout EOF.
Its first version incorrectly started that latter clock at input EOF; the
resulting timeout and forced cleanup remain recorded. No production bytes or
SDK timeout were changed for the corrected observation.

## Actual qualification and remaining scope

The new HIA framing leaf passed 70 real native calls, including exact command
frames, growth, malformed fields and result classifications. The actual default
runtime was linked and packed with 130 members, 131 physical HIA images and 138
runtime HIA images. Its ELF is 28,925,952 bytes with SHA-256
816bd3e4eaf6d7d37212a360ea47594203f363085938550cc3dd7bfb930dc01d.

The same default MCP process completed initialize, initialized, tools/list and
the two real installed ROG file_info/binary_read calls. Two additional actual
runs retained one and two blocked direct OpenSSH children while another
configured host completed, then followed SDK drain, caller destruction and
owner cleanup. Both exited zero without adopted descendants.

These default observations are separate from the original 19-method gate;
neither is a claim that all 136 public handlers are complete. The configured
ROG administrator route still uses its existing external Python ProxyCommand.
That external transport boundary is recorded and has not been replaced here.
The 8 MiB SSH profile is not the REA worker profile or its much larger reply
allowance.
