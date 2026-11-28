# Exact native binary diagnostics

This frozen qualification builds a pure HIA formatter for the existing HBRDS001 error response.
Its production leaf contains only HIA instructions and immutable Linux/Unicode data. Python is
used for source authoring, build driving, actual original reference capture, and byte custody.
There is no Python, libc, or dynamically loaded Unicode table on the formatter's runtime path.

The input-only domain is committed before the first native application call: 4,095 Linux errno
values, 240 filename variants, all 1,112,064 Unicode scalar values split into 17 planes, and
112 literal exceptions. An additional 280 exact boundary calls cover malformed messages,
capacity failures, dirty workspaces, output tails, and high unsigned sequence identifiers.

The fourteen-class existing wire remains unchanged. ESRCH and ECHILD use its generic OSError
tag and are rendered as ProcessLookupError and ChildProcessError, matching the original
CPython exception constructor. The generated data explicitly targets Linux x86_64,
LC_MESSAGES C, and Unicode 15.0.0. Other platform/localization behavior is not claimed.

Every original input/result and every native input, entire before/after workspace, entire
before/after output, return value, process stream, build receipt, and compiler source is retained.
Eight physical corruptions and two complete relocations challenge an execution-denying reader.
Successful captured semantics are never replayed to repair a pure reader. Failures retain their
complete evidence. Each process has its original budget: 60 seconds for ordinary work,
180 seconds for pure evidence reading, 900 seconds for native build.

This is a private formatter gate. It does not claim a completed read gateway, remote transport,
public tool registration, asynchronous lifecycle, or replacement of the complete runtime.
