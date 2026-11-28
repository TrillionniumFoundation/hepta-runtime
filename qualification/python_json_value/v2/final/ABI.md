# CPython JSON value owner

This HIA owner receives complete UTF-32LE documents from the separately qualified
Python JSON byte decoder. HPYJSQ01 has eight little-endian u64 words: magic,
command, primary code point count, auxiliary code point count, parse recursion
budget, encode recursion budget, comparison recursion budget and combined payload
byte count. Text spans follow at offset 64. Code points through 0x10ffff, including
unpaired surrogates, are admitted. The combined limit is 8,388,608 code points.

Parse and encode budgets are 1..20000. Comparison budget is 1..20000 for command 5
and zero for every other command. These are remaining C-operation budgets at the
actual original call site, not sys.getrecursionlimit(). At the frozen CPython
3.12.3 Linux release reference call sites they are parse 9997, encode 9997 and
comparison 9998. The original-only low/high/error profiles retain every actual
return, exception, input and observed operand. Production callers must bind their
own actual call site before installation. Constructed operand qualification may
use a larger parse admission budget while independently binding encode/compare
budgets to those actual operations.

Workspace minimum is 16,480 + 40*combined_codepoints. Invalid input returns u32 -1,
short workspace returns -3 and short output returns -2. Input never changes.
Input/workspace refusal leaves the whole workspace and output unchanged. Later
refusal leaves the entire output unchanged; workspace is scratch. Successful
output writes only its returned byte extent; the remaining output stays unchanged.

Commands are 1 parse/inspect, 2 strict string subscript, 3 sorted-key Python JSON
dumps, 4 dictionary update then sorted dumps, 5 Python equality and 6 dictionary
get with None default. Commands 2/6 take an unquoted ASCII key of at most 96 code
points. Commands 4/5 take a complete auxiliary JSON document. Command 4 requires
an auxiliary dictionary; this is the private production update shape. Commands
1/3 have no auxiliary text. Arbitrary decoded object keys remain supported.

HPYJSR01 has eight u64 words: magic, kind, tag, truth, float bits, count, payload
encoding and payload byte extent. Kind 0 exposes a value: tags 0..7 are None,
false, true, integer, float, string, list and dict. Strings are complete UTF-32LE;
integers are canonical ASCII decimal; containers expose their complete original
UTF-32LE lexical span; None/bool/float have no payload. Encoding 1 is UTF-32LE and
2 is ASCII/UTF-8. Kind 1 carries complete ASCII json.dumps output, kind 2 the
comparison boolean, and kind 3 a complete class-prefixed exception in UTF-8.
Kind 3's tag is a private diagnostic selector, not an external exception code.

The parser validates every syntax/number before selecting duplicate keys. Sorted
serialization uses decoded Unicode key order. Dictionary updates retain the
first insertion position and last value. Equality visits list elements and the
left dictionary's keys in original insertion order, observes short circuits,
and accounts for CPython identity shortcuts for singleton values, cached small
integers, empty/Latin-1 strings and decoder NaN/Infinity constants. Containers
from independently parsed inputs have distinct identities. Numeric equality
supports arbitrary admitted integers, binary64, booleans, signed zero and NaN.

Decimal conversion and shortest Python float printing use the pinned Hepta
integer algorithms. Integers honor the original 4300-digit default. JSON
NaN/Infinity, Unicode escapes, surrogate pairs and lone surrogates are retained.
The measured C recursion behavior includes container entry, constant callback,
comparison, encoding, StopIteration/ValueError construction and JSONDecodeError
construction. Full errors at the boundary remain distinct, including the
'while calling a Python object', plain, decode, encode and comparison variants.

This private component has completed the main actual original/native domain,
the measured C-recursion boundary domain, full uploaded archive reading and
the main domain's physical negative and relocation controls. FINAL_HANDOFF.json
binds the exact source, image, domains and retained evidence. Public callers still
must bind their own call-site budgets and complete their integration qualification.
