# Text result constructor, HRTCRQ01

This owner implements a single text content block through RMCP 3.9.0
CallToolResult::success / CallToolResult::error, then the selected protocol policy.
It receives complete raw UTF-8 text. It does not parse that text as JSON.

## Request

All fields are little-endian u64. A request is exactly 64 + text length bytes.

| Byte offset | Field |
|---|---|
| 0 | HRTCRQ01 |
| 8 | operation, exactly 1 |
| 16 | is_error, 0 or 1 |
| 24 | policy: 0 current constructor, 1 legacy complete discriminator removal, 2 current protocol |
| 32 | raw UTF-8 text byte length |
| 40, 48, 56 | reserved, zero |
| 64 | complete text bytes |

For this result type, current protocol cache filling does not add cache hints,
so policy 2 has the same result wire as policy 0. Scope annotation must use
policy 0 and is_error 0 before its original budget check.

## Completed response

The HIA entry returns **64**. This is a descriptor length, not the payload extent.
The complete owned output extent is **64 + u64 at byte 40**.

| Byte offset | Field |
|---|---|
| 0 | HRTCRS01 |
| 8 | status 0 |
| 16 | copied is_error |
| 24 | copied policy |
| 32 | result wire offset, 64 |
| 40 | complete serialized result wire length |
| 48, 56 | reserved, zero |
| 64 | JSON result bytes, without LF |

The result has one text content block, isError explicitly false or true, no
structuredContent and no _meta. Current constructor/policy 2 includes
resultType complete. Legacy policy omits that complete discriminator. The output
is borrowed until its caller has completed delivery; the caller must not release
or overwrite it early.

## Capacity and return contract

The image uses history.v1: input 128 MiB, output 128 MiB, workspace 256 MiB.
Its workspace requirement is 16384 + complete text bytes. There is no 8 MiB text
quota. A caller admitting 64 MiB raw text must admit header + text, and must also
provide the **complete escaped output** capacity reported by the owner.

Return 0xffffffd0 means a real capacity request. The first 32 output bytes are:

| Byte offset | Field |
|---|---|
| 0 | HGRWS002 |
| 8 | 1 workspace, 2 output |
| 16 | required complete capacity in bytes |
| 24 | reserved, zero |

The caller grows the designated allocation, and invokes the stateless owner again
with the complete original input. Output requirement includes its 64-byte header.
This is not a child suspension or a partial publication. Counting state is reset
on every invocation. There is no finished wire extent on a growth return.

Other terminal returns are 0xfffffffe when output is too small even for the
32-byte growth descriptor; 0xffffffff for an invalid private frame or invalid
UTF-8; and 0xfffffffc for an unrepresentable resource size. These returns carry
no completed result extent. Callers must not truncate a result to make it fit.

## Qualification boundary

This source document is not a qualification receipt. Native captures, the fresh
target Rust constructor comparison, and actual public graph publication each
require their own retained evidence. Full SDK, tasks/futures, asynchronous
transport, cancellation timing, production activation and old-stack removal
remain outside this owner's scope.

