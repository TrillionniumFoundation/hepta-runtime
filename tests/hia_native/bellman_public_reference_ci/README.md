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

## Exact SDK argument model

The first frozen public run completed all 1,394 records, then its reader
rejected the assumption that a root `serde_json::Value` and the SDK's root
`JsonObject` admit identical inputs. In particular, the raw-value marker key
at the arguments root is a literal unknown field in the SDK. A nested `Value`
retains the target's separate raw-value behavior. The complete failed artifact
and its original failure conclusion are retained.

The input domain and all public Rust fixture bytes remain unchanged in this
follow-up. A separate locked original binary now parses every complete input
with the actual `ClientJsonRpcMessage`, applies the actual SDK
`parse_json_object` to its actual arguments map, and invokes the unchanged
original plan for every accepted parameter. Both actual original model text
and actual service-loop text are compared in full. The existing
`expected_start` field in the unchanged domain remains the historical private
typed admission observation; public start/completion counters are instead
checked against the newly observed actual SDK model, with no case exemptions.

Model records use `HBPMOR01` and eleven U64 words: sequence, opcode, session,
model kind (0 non-tool, 1 Bellman arguments map, 2 tools/call custom request),
status (0 success, 1 typed error, 2 business error, 3 non-tool/custom), canonical
argument bytes, text bytes, actual monotonic start/end, zero, zero. The complete
canonical argument map and text follow. The model process has a 60-second
limit inside the unchanged 180-second public stage. Pure readers stream the
large inputs and responses without executing any original or native code.

The SDK's uncorrelated protocol errors omit the `id` member entirely. The
domain's `null` response-ID marker denotes this absence; an explicit `id:null`
does not pass the reader. Inline-session recovery pings intentionally retain
their original missing metadata, and therefore return the SDK's complete
required-metadata error. The legacy pings return empty results. Both outcomes
prove that the same connection consumes the recovery request; no input was
removed or rewritten after observing these boundaries. A relocated stronger
reader separately binds its own complete source package and the unchanged
producer package, keeping both inside the existing read-only guard.

### Source-only corpus loading

The v3 reader completed the full SDK data comparison but its strict guard rejected three importlib probes for a nonexistent `reference/__pycache__/qualify_bellman.cpython-312.pyc`. The caught probes remained recorded as refusals; the v3 run is a failure. Version 4 loads the exact frozen Python corpus source directly, avoiding bytecode-cache probing. It keeps the guard unchanged, preserves every corpus input and wire byte, and changes no Rust, HIA, SDK, protocol expectation, deadline, or original evidence.
