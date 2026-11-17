# Closed native HIA audit JSON codec

The private audit codec is qualified at source commit
`15f560cf20834b5a24844e0eb7e699dcc6dd81ec` under
`tests/hia_native/audit_json`. Its complete 36-file source manifest is
`0bf9ff533011ce1435b9c8630681d7117dd79fb211dae6573c07c9d669da45a3`.

The implementation is `native/audit_json.hepta`: 126,320 bytes, SHA-256
`5146e5c42028692933762ce68bd9c62d52f9760d8ce378124e3888edacb4255b`.
Its 46 functions, 739 blocks and 2,102 HIA instructions compile to a
161,260-byte flat native image with SHA-256
`76122331b305e654b6175a3d0a975d080815ee1cfcf542ea837d8aecdb83b2fc`.
The flat runtime image requires neither Rust nor Python.

## Actual original and native comparison

[CI 43999196601](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/43999196601),
job 133758725787, completed successfully. All 3,511 original Rust and native HIA
cases agree byte for byte: 2,624 successful results, 850 invalid-input refusals
and 37 capacity refusals. The original reference uses the unchanged target
six-field generic audit record, durable state, and four-field archive anchor.
It retains all 11 locked dependency archives and 464 dependency source files,
5,895,341 bytes, with their exact checksum closures.

The cases cover all 720 record field orders in owned and borrowed forms, all
24 anchor orders, map and sequence forms, required and optional fields, enum
representations, all unsigned integer limb boundaries, Unicode and escapes,
invalid types, exact compact serialization, canonical projection constraints,
the original 2,048-byte storage read limit and buffer capacity behavior. The
frozen input author does not synthesize expected semantic outputs.

The actual original process took 0.020 seconds and the native process 0.630
seconds, each with its unchanged 60-second limit. Their complete stdout streams
are 755,580 bytes with SHA-256
`bb5e55a33a92b3231cc607f1232cb82cfd62dee86c9c66c60c65728eb7f81f7f`.
Every physical source, output and workspace buffer before and after each call
is retained: 86,583,064 logical physical bytes, including all guard tails.

## Independent readers and physical controls

Twelve actual evidence mutations are rejected with their specific source-owned
reason. Two complete relocations and two post-refusal admissions preserve the
original result. All 16 physical-control proofs and both full reader proofs
pass twelve execution/write guards each, for 216 explicit guard probes.

The semantic reader took 1.218 seconds, physical controls 43.607 seconds and
final complete reader 40.596 seconds; each retained its 180-second budget. The
whole private gate took 100.908 seconds. Reader execution performs no native
or Rust calls and writes no protected files.

The complete exported artifact is 14290704076. Its ZIP is 30,353,197 bytes,
SHA-256 `9f9e16d5fcc317322fae1364ff5256db8fe6af99f232dc5c381d2b547308e94a`.
Its TAR is 30,379,750 bytes, SHA-256
`e700e29132638423dba19001407c3a3dffe7748442996c6a92824d7c2ba587d9`.
Lossless byte/mode deduplication retains all 28,434 logical paths and
1,140,708,946 logical bytes through 1,650 unique objects totaling 102,197,397
bytes. The independent reader frozen at
`a24e0129552c3ab573f800ebb7f0d37b02a83ac5` completely reads all objects, source
bindings, original/native streams and guarded proofs; it passed in 2.320
seconds without local HIA or Rust execution.

The temporary ZIP download was deleted only after a complete byte and mode
comparison to the retained complete ZIP. No qualified source or old production
runtime was deleted by this component's cleanup.

## Caller boundary

Use the exact `ABI.md` from the source commit. The 24-byte `HAJRQ001` frame
selects owned record decode, anchor decode, record serialize, anchor serialize,
or borrowed record decode. Decoded records use a canonical 128-byte `HAJPR001`
header and three trailing UTF-8 strings. Workspace is at least 8,192 bytes.
Invalid input returns `0xffffffff`; insufficient capacity returns `0xfffffffe`.
Both leave the output unchanged.

This leaf preserves typed values and exact successful serialization. It does
not expose original Serde diagnostic text. Actual filesystem identity,
authorization, filename checks, storage write limits, retention and archive
publication remain in the caller. In particular serialization is allowed to
exceed the storage record limit so the actual storage caller can enforce its
original policy before opening a destination.

The actual audit persistence/caller composition, public handlers, complete SDK
and asynchronous behavior, all 136 target handlers, production activation and
old-stack removal remain outside this private codec qualification.
