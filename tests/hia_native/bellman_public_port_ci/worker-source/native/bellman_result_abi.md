# Bellman result serializer

This component emits the complete 36-field JSON value returned by the pinned
target `weight_bellman::solve`. It is a private serializer, reached after the
numerical worker and canonical commitment owner succeed.

Input `HBLMRQ01` has eight little-endian u64 words: magic, operation 1,
complete core-frame length, complete commitment-frame length, elapsed f64
bits, and three zero reserved words. The complete `HIABPLN1` and `HBCMTRES`
frames follow. The implementation digest and request digest come from that
commitment owner. They are not caller-provided public authority.

Output `HBLMRS01` has eight u64 words: magic, status, complete JSON length,
required capacity, and four zero words. Status 0 appends the full JSON body.
Status 2 requests `20480 + state_count * 256` workspace bytes; status 3
requests the exact output capacity. Both growth responses occupy 64 bytes.
Invalid frames return `0xffffffff` before mutating either borrowed buffer.
An output shorter than 64 bytes returns `0xfffffffe` after input validation.
Workspace growth leaves all workspace bytes unchanged. Output growth does
not publish a partial JSON body. `serde-json.v1` admits the bounded input.

Result keys use serde_json::Value's ordered map representation; each state
is `{action,q,value}` and each absent action remains null. The imported
integer-only finite-f64 formatter preserves negative zero and exact target
float text. No Python or Rust code is embedded in the native component.

Qualification compares the complete output with the unchanged original
result expression and original state/dimension declarations. The reference
uses an explicit elapsed-bit observation fixture, so this test establishes
serialization only. The actual clock, 30-second checks, two-worker permits,
cancellation lifetime, public typed validation and routing are separate
owners that must be joined before the full tool can be admitted.
