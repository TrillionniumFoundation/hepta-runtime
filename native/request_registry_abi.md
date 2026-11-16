# Request registry private owner

This image owns request generations, typed JSON-RPC ID mappings and retained cancellation/completion state. It does not own a transport, public scheduler, handler execution, worker interruption or runtime destruction. The fixed SDK comparison uses controlled handlers through unchanged rmcp 3.4.1. All production activation and whole-runtime replacement flags remain false.

Input is `HRQREG01` plus seven little-endian u64 fields: `operation, generation, ID kind, key length, drain reason, 0, 0`, followed by the entire key. Kind 1 is an eight-byte signed-i64 bit representation; kind 2 is complete UTF-8. Integer and string IDs are distinct. Operation 0 initializes; 1 registers; 2 removes/cancels the current mapping; 3 completes a generation; 4 retires an already completed generation; 5 inspects; 6 cancels the parent; 7 starts drain (reason 1: EOF/5000 ms; reason 2: parent/2000 ms).

Success returns 64 bytes: `HRQRR001`, then `operation, status, generation, related generation or required extent, decision, retained count, mapped count`. Status 2 requests physical workspace growth. Preserve the full old workspace, zero the new region, check u64 arithmetic and retry the same call. No fixed live-request or total-key quota is introduced by this owner; LP64 representation and actual allocation resources still apply.

Workspace starts with `HRQRS001` and `next generation, used extent, retained count, mapping count, parent cancelled, drain reason, 0`. Each aligned record has six u64 fields: `extent, generation, ID kind, key length, flags, 0`, key bytes and zero padding. Flags are cancelled=1, completed=2, mapped=4. The unused tail remains zero. Input/state/capacity/resource refusals preserve both declared buffers in full. Generations never wrap into a reused identity.

Completing an older duplicate-ID generation removes the current mapping and cancels its token, matching the original SDK map. Response emission is a caller decision, not observed OS delivery. EOF and parent drain durations do not instruct the caller to kill workers. Retirement requires actual completion.

Qualification uses the generic `history.v1` image carrier without a standalone ELF. Native private and SDK-schedule corpora retain full input, output-before/after and workspace-before/after as 4096-byte content-addressed chunks. The original recipe follows complete native admission. Pure readers never execute HIA/Rust or restore live fixtures.
