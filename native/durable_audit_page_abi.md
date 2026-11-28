# Durable audit page selection, private ABI 1

This component owns the original history sort/cursor/filter selection and
archive-page JSON rendering. It receives already captured rows; the caller must
provide the real owner capability, guarded archive/index snapshot, current
active state, and monotonic query deadline. This module alone supplies no
filesystem, archive integrity, clock, or public owner authority.

Input is `HRAQP001`, 192-byte header followed by 256-byte rows. Header words:
operation at 8 (1 history, 2 archive); row count 16; limit 24 (1..32);
cursor-present 32; archive total 40; now/deadline 48/56. Bytes 64..127 are the
64 lowercase hexadecimal owner; 128..191 are a matching-format cursor or zeros.
History requires total/now/deadline zero and at most 512 rows. Archive requires
at most limit+1 rows, all owned, already strictly ordered, total >= row count,
and an absent cursor (the indexed range has already applied it).

Each row contains request ID at 0..63, owner at 64..127, tool bytes in a zero
padded 64-byte area at 128, tool length at 192, state at 200, full timestamp
low/high at 208/216, elapsed-present/value at 224/232, actual-active boolean
at 240, and a zero reserved word at 248. Rows have distinct IDs.

History filters by owner, sorts by the full unsigned 128-bit timestamp and ID,
checks the owner-local cursor, and emits the original page and active-state
projection. Archive renders the already guarded ordered range with original
next-cursor and total semantics. It does not substitute a full directory scan
for the original indexed archive query.

Output `HRAQR001` has a 32-byte header: diagnostic at 8, JSON length at 16,
total length at 24, followed by exact original compact JSON.
Diagnostics are 0 success, 1 parameters, 2 cursor, 3 selected timestamp cannot
be represented by the original JSON number domain, 4 deadline, 5 wire bound.
Private malformed input returns `0xffffffff`; short output/workspace returns
`0xfffffffe`. Complete original Rust JSON bytes are compared in qualification.
