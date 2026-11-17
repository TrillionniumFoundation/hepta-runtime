# Frozen audit lifetime reader recovery

This package reads the unchanged complete archive from producer commit
`c690fbd394aab187d58d43f7c9d27b09704cb35b`, run `43988453363`.
The producer completed all 40 semantic subprocesses. Its subsequent reader
failed because `capacity_beyond_512` has five assertions in the frozen shared
Rust body and both actual output streams, while DOMAIN.json registers four.

The sole semantic-reader correction supplies five as that expected count.
The producer source, manifest, domain, capture, process records, binaries,
physical buffers, and FAIL gate remain byte-for-byte unchanged. Every other
reader predicate and every original process budget remains in force. The
recovery identity appears explicitly in the result and is protected by the
same twelve-probe read-only guard, alongside the producer source and capture.

No Rust build, HIA execution, native mapping, or semantic replay belongs to
this package. A successful read qualifies only the private ACTIVE/READ_PINS
lifetime owner. Public handler activation and whole-runtime replacement
remain false.
