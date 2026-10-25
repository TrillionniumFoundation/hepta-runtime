# Deferred design: merging worker and owner file-boundary checks

Decision: do not implement under the current preserve-all-checks boundary.
This is a design disposition, not an experiment or a measured improvement.

A25 performs the complete read/hash and final FD/path stamp checks in a
blocking worker, followed by a fresh owner-side `checked_file` boundary check.
A proposed handoff would retain each original `File` and combine the last two
checks on the owner. It could remove one full path traversal and one metadata
query per pinned file without reducing complete hash bytes.

The proposal is deferred for three reasons:

- It merges two observations made at different times. A pathname temporarily
  changed and restored between those observations can produce a different
  rejection outcome. Equivalent final acceptance predicates do not establish
  preservation of every existing intermediate observation.
- A background finalizer followed by a successful reply introduces another
  scheduling gap before the caller uses authority. Avoiding that gap requires
  normal finalization in the caller's current owner poll, plus independently
  supervised finalization when that caller is cancelled.
- Permits would have to cover reads, ready results and finalization. Two slots
  could retain twelve input FDs, with a conservative temporary-descriptor
  budget of twenty for the validation subsystem. Shutdown and exceptional
  result drops would require additional ownership state and regression tests.

Full pre/post-agent hashing, all current identity and permission checks, fatal
late-error handling, original deadlines, and cancellation remain requirements.
No source change, qualification, throughput result or CPU improvement is
claimed for this design. A25/D4 evidence and immutable sources remain separate
from subsequent A26 correctness work.
