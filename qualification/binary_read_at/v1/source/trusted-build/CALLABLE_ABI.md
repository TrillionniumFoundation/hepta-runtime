# Binary read native callable

The fixed Linux x86_64 callable implements create, invoke, release and destroy with the same private arena and loan rules as the qualified text publication callable. It embeds three immutable HIA entries: binary_read_body, binary_codec and stat_version. It uses direct kernel system calls; runtime Python and libc are absent. The callable contains no path authorization, version arithmetic, SHA256, Base64, read-loop or output policy: these are implemented by the HIA body and children.

The callback is an optional trusted observation binding. A null callback executes the same owner chain without a journal. Invoke accepts a complete HBRDQ001 frame and returns 64 on a borrowed complete HBRDS001 result. The complete result pointer is context+104 and its extent is context+168. Release is required before another invocation or destruction. Active and borrowed contexts reject destruction, and terminal results require an empty owned descriptor set.

The private context remains 4096 bytes. Body entry, codec and stat entry occupy offsets 16/24/32; callback/context 40/48; state 56; input pointer/capacity 64/72; workspace 88/96; output 104/112; reply 120/128; child output/workspace pointers 136/144; result extent 168, return 176, descriptor count184, generation192, current input200/208, sequence216, child/OSoperation224, raw result232, reply extent240, body call count248, eight owned descriptors256..319. Current child entry/output capacity/workspace capacity are320/328/336. Child output owns1,400,832bytes plus a guard page; child work owns4096 plus a guard page. All variable arenas retain their old complete bytes on growth, zero their extensions, and have a final inaccessible page.

The fixture alone owns stdin/stdout/FD3 and two contexts. HBRDFQ01/HBRDFR01 transport exposes invoke1,release2,destroy3,completecontext4,workspace5,output6,input7,observedcreate8,unobservedcreate9. Its HBRDJR01 journal records complete payloads with a128-byte header. Events1/2 arebody input/completeoutput;10/11 completebody workspace before/after;12 completebody output before;3/4 workspace before/after growth;5 childinput;6/7 completechild output/workspace after;13/14 completechild output/workspace before;8 rawOSrequest;9 completeowned resume. This fixture is qualification-only and is not a public runtime route.

This checkpoint only builds and rechecks the immutable native image. No binary file operation, reference method or application callable is invoked by its CI workflow. Actual original/native filesystem comparison and lifecycle qualification remain separate required gates.


## Borrowed parent successor

The additional fixed binary_read_body_invoke_at export takes a graph-owned
parent FD separately from a complete HBRDFD01 packet. It neither duplicates nor
closes that FD. Its transient context capability occupies offsets 344 and 352;
owned file slots remain unchanged. Closing a borrowed parent through the raw
effect gate is refused. The HIA ABI and exact 63-function preservation are in
ABI.md and the new composition receipt.

The private fixture retains two parent capabilities. Command 10 holds a NUL-
terminated directory path; command 11 invokes at the session's held parent;
command 12 closes that parent's fixture-owned FD; command 13 returns its actual
144-byte Linux stat record. Those commands are not registered public tools.

Private FD4/FD5 synchronously notify and acknowledge each observed raw OS
request, using a fixed 64-byte HBRDHK01 record and an eight-byte zero ack. The
notification contains generation, body call, request sequence, operation and
three arguments. The observer cannot substitute an OS or HIA result. A frozen
fixture actor may perform an actual filesystem mutation before acknowledging.
Observer-disabled contexts have no callback, no journal and no notifications.
Only FD0/1 and optional graph callbacks matter to the standalone production
callable; these fixture ports are not exposed by a public tool.
