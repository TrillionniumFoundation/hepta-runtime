# Fixed get_info private ABI

The function accepts three borrowed buffers and returns u32. It has no child
edges, persistent state, configuration input, global dispatch slot or public
request selector. Its workspace is unchanged.

## Input: HRTGIQ01, exactly 32 bytes

| Offset | Type | Value |
| --- | --- | --- |
| 0 | 8 bytes | HRTGIQ01 |
| 8 | u64 little endian | 1: construct the fixed current get_info result |
| 16 | u64 little endian | 0 |
| 24 | u64 little endian | 0 |

The operation constructs the exact target method's ServerConfig:
protocol version from the SDK V_2026_07_28 constant; experimental channel from
the original CLAUDE_CHANNEL_CAPABILITY constant with empty settings;
resources.subscribe = true; tools present with default omitted listChanged;
Implementation::from_build_env identity from the actual RMCP crate; and the
original Rust instruction literal. Unset optional fields are omitted.

## Complete output: HRTGIS01, 64-byte descriptor followed by wire

| Offset | Type | Value |
| --- | --- | --- |
| 0 | 8 bytes | HRTGIS01 |
| 8 | u64 little endian | 0: success |
| 16 | u64 little endian | 1: fixed get_info operation |
| 24 | u64 little endian | 0 |
| 32 | u64 little endian | 64: wire offset |
| 40 | u64 little endian | Complete wire byte length |
| 48 | u64 little endian | 0 |
| 56 | u64 little endian | 0 |

The entry returns 64, the descriptor size. The complete valid output extent is
64 plus the length at offset 40. The caller must consume that complete extent,
not confuse the return value with the JSON length. Wire is UTF-8 JSON with no LF
and no outer JSON-RPC envelope. The caller owns the output allocation.

## Capacity and failure returns

If output capacity is at least 32 but smaller than the required complete
extent, the owner returns 0xffffffd0 and writes a 32-byte HGRWS002 frame:
magic at 0, kind 2 (output) at 8, required complete extent at 16, zero at 24.
The caller grows its output and repeats the unchanged 32-byte request.

Output below 32 returns 0xfffffffe without writing. An invalid fixed request
returns 0xffffffff. An internal field-writer length mismatch returns 0xfffffffc;
it is an invariant failure, not a business response. No input, workspace or
output size profile is expanded by this owner.

The standalone qualification uses the existing standard NativeBuild profile,
but only this fixed input and fixed result are qualified. The HIA helpers for
u64 read/write are copied by direct function/call relocation from the unchanged
shared text constructor source 3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d.
