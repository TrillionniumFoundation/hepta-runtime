# CPython JSON value source contract

This HIA owner receives complete UTF-32LE documents produced by the separate
Python JSON byte decoder. Its private HPYJSQ01 header has eight u64 words:
magic, command, primary code point count, auxiliary code point count, parse
recursion budget, encode recursion budget, zero, and combined payload byte count.
The two complete text spans follow at offset 64. Every code point is <=0x10ffff;
unpaired surrogates are valid. Total code points are <=8,388,608. Caller recursion
budgets are explicit 1..2000 and must be bound to the actual reference call site.
Workspace minimum is 16,448 + 40*total_codepoints; output refusal is atomic.

Commands: 1 parse and inspect; 2 strict string subscript; 3 sorted-key Python
JSON dumps; 4 dictionary update then sorted dumps; 5 Python JSON-value equality;
6 dictionary get with None default. Commands 2/6 take an unquoted auxiliary key
of <=96 ASCII code points. Commands 4/5 take a second complete JSON document.
Commands 1/3 have no auxiliary text. Typed upload and inode owners use only fixed
ASCII field names for lookup; arbitrary decoded object keys remain supported.

HPYJSR01 output is eight u64 words: magic, kind, tag, truth, float bits, count,
payload encoding and complete byte extent. Kind 0 exposes a value; tags 0..7
are None, false, true, integer, float, string, list and dict. Strings return full
UTF-32LE decoded content, integers canonical ASCII decimal, containers complete
original UTF-32LE source text, and None/bool/float have no payload. Encoding 1
is UTF-32LE and 2 ASCII/UTF-8. Kind 1 returns complete ASCII json.dumps text,
kind 2 the actual comparison boolean, and kind 3 a complete class-prefixed error.
Container source text retains original lexical form, while parsed lookup and
serialization implement last duplicate selection and decoded key ordering.

Decimal-to-binary64 conversion and shortest Python float printing use the pinned
Hepta integer algorithms. JSON admits NaN/Infinity, arbitrary integers through
CPython's 4300-digit default, strict escapes, surrogate pairs and lone surrogates.
Input text is never changed. All syntax and number checks precede duplicate
replacement. This author source has made zero application calls and makes no
semantic-qualification claim. Recursion profiles, complete native buffers,
actual original values/errors, read-only evidence and negative controls must be
qualified before any production caller may install the owner.
