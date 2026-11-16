# Bellman public SDK reference

This fixed reference observes the unchanged target `weight_bellman.rs`, its
exact server method and exact `get_info` method through rmcp 3.9.0's real
`ToolCallContext`, `AsyncMethodAdapter`, service loop and duplex transport.
It uses the same locked Rust 1.95.0 dependency closure as the complete private
Bellman reference. Rust execution is allowed only in fresh CI.

The complete 683 original inputs run once through the original typed and plan
observers and once through each of two real SDK sessions: a 2025-11-25
initialization lifecycle and 2026-07-28 inline request metadata. The public
envelope retains all 13 non-object input cases; its model boundary is checked
separately from the tool's typed-object boundary. Missing or null arguments use
the SDK's default empty object. All other non-object arguments are observed at
the SDK custom-request boundary.

Each session also executes 12 fixed argument/transport controls, including
exactly 16 MiB and over-limit lines. Recovery pings have unique request IDs.
Both sessions close normally, and every byte remaining after EOF is retained
and required to be empty. The fixed domain contains 1,394 fixture records and
1,366 actual public tool input cases. Each exchange is limited to 60 seconds,
the public process to 180 seconds, and the workflow to 15 minutes.

The binary fixture is test-owned. Input records are `HBPOREQ1` followed by seven
little-endian U64 words: sequence, opcode (1 wire, 2 close), session, wire bytes,
expected response lines, zero, zero; the complete wire follows. Output records
are `HBPORES1` followed by eleven U64 words: sequence, opcode, session, input
bytes, output bytes, actual monotonic start/end nanoseconds, cumulative actual
dispatch/start/completion counts, zero; complete SDK output bytes follow.

The pure reader verifies all package files, unchanged source fragments, every
locked registry archive and source member, all process streams, all frames and
every complete tool text. Only the actual elapsed field is normalized between
independent original executions, and each physical duration is checked against
the enclosing actual monotonic interval. The reader runs with execution,
foreign reads and mutation denied and checks the complete filesystem snapshot
before and after eleven refusal probes.

This reference does not implement or qualify the complete target audit/router,
tool discovery annotations, concurrent request cancellation, HTTP, the HIA
pending host registry or the complete runtime. Those flags remain false.
