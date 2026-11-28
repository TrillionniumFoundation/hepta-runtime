# Private result publication v1

This owner is an internal native object, never a public MCP authority API. The
production adapter selects its private arena; a request ID does not select an
arena. A generation only rejects stale operations within that already owned
arena. The production config MCP profile remains serial. This owner does not
replace the nine original filesystem hint callers or their scoped scheduler.

Entry: `f0(readbuf, mutbuf, mutbuf) -> u32`. The workspace is a growable private
mapping. Every byte reference retained by HIA is an offset, never a raw pointer.
The fixed native adapter may relocate the mapping only between HIA calls. There
is no application-level cumulative quota introduced by output windows or a
fixed chunk count. LP64 representation, checked counters, and actual memory
and I/O resources still bound successful execution.

## Private request and response

Request: `HRPQ0001` followed by seven LE u64 words: operation, generation,
sequence, arg0, arg1, payload_length, reserved zero; then exactly the payload.
The per-call payload is bounded by the caller's window, not the result length.

Response: `HRPR0001` followed by seven LE u64 words: status, generation, phase,
arg0, arg1, confirmed_output_bytes, flags; then optional PULL bytes.

Status zero is success. Phases: 0 vacant, 1 constructing, 2 sealed, 3 publishing,
4 fully acknowledged, 5 cancelled/dropped. Flags bit 0 reports nonzero confirmed
bytes; bit 1 reports publisher ownership transfer, not an OS write attempt; confirmed bytes are delivery observations,
not evidence that an external file effect failed.

| Op | Fields | Meaning |
|---:|---|---|
| 1 CREATE | generation/sequence=0; arg0 format 0 raw, 1 JSON string, 2 MCP result, 3 trusted MCP prefix; arg1 isError 0/1 | Create a new private generation. Valid only vacant or dropped. |
| 2 APPEND_BASE | matching generation, payload bytes | Append to base builder. Incremental UTF-8 validation; no mutation on invalid chunk. |
| 3 SEAL_BASE | matching generation; no payload | Require a complete UTF-8 base; prevent further base writes. |
| 4 HINT_BEGIN | matching generation; no payload | Start one hint, including a possibly empty string. |
| 5 APPEND_HINT | matching generation, payload bytes | Append to current hint, validating UTF-8 across chunks. |
| 6 HINT_END | matching generation; no payload | Seal a complete UTF-8 hint. No deduplication or normalization. |
| 7 SEAL_ALL | matching generation; no payload | Base must be sealed and no hint may be unfinished. |
| 8 START | matching generation; no payload | Transfer sealed result to the publisher. |
| 9 PULL | matching generation; no payload | Return unacknowledged window bytes, arg0=sequence, arg1=current window offset. Repeated PULL is identical. |
| 10 ACK | matching generation and pending sequence; arg0=current window offset; arg1=positive accepted byte count | Advance only the reported actual write; refuse stale, excessive, duplicate or mismatched ACK. |
| 11 CANCEL | matching generation; no payload | Retire after caller has settled any in-flight syscall; preserve delivery observations. |
| 12 DROP | matching generation; no payload | Retire ownership after syscall settlement; old generation is no longer usable. |
| 13 APPEND_PREFIX | matching generation, payload bytes; format3 only | Append already validated, trusted HIA JSON-RPC/MCP prefix. Not request-selected JSON authority. |

All unused fields must be zero. Ordinary state responses use arg0=base byte
length and arg1=hint count. A PULL response is 64 bytes plus its exact payload.
After all bytes are acknowledged, PULL returns an empty payload and phase4.
Format0 returns exact append_hints bytes. Format1 quotes that text with the
locked serde string escaping. Format2 emits the compact 2025-06-18 transport
CallToolResult: content/text plus isError, without resultType. Format3 emits
the trusted HIA-built prefix, quoted composed text, and the same result suffix
plus the closing JSON-RPC object. Prefix is appended before SEAL_ALL.

Zero hints reuse the base chain directly. Nonzero hints append two LF bytes,
then the seven bytes of `⚠️ `, each full hint, and LF. The complete result is
constructed and sealed before START. A chunk may split a UTF-8 scalar; the
logical string's terminal seal decides whether UTF-8 is complete.

Domain refusals: INVALID=0xffffffff, CAPACITY=0xfffffffe, STATE=0xfffffffd.
These preserve output and the complete private mapping. GROW=0xffffffd0 is an
adapter continuation, not a tool-domain capacity error. It records only a
required extent in the private growth record. The adapter either grows and
retries the same operation or reports a real allocation failure without
discarding the previously valid object. Per-call output must fit its response;
production supplies a fixed sufficient window before any external effect.

CANCEL/DROP are trusted lifecycle operations after syscall settlement. A
late ACK cannot mutate a new generation. Cancellation after START never
changes an already completed tool effect into failure or authorizes replay.

## Qualification surfaces

The separate owner fixture uses length-prefixed private frames and responses.
The publication fixture constructs through the same HIA owner and publishes
only after final sealing, retaining actual partial-write/ACK receipts. Those
fixtures are not public tools or proof of production route replacement. The
production integration changes the existing config_mcp text-result path and
retains its original tools, source owners and protocol semantics.
