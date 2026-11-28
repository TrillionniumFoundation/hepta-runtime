# Binary parameter evidence recovery

The original source remains 6bd6b3092854cdf1f5429a246fe31922aed603db.
That run completed all 1,388 original/native pairs, 170 ABI controls and 8,143
native calls. Its initial complete readonly comparison passed. The run remains
FAIL because a physical-control reader attempted to read the frozen case schema
from a source directory omitted from that reader's declared roots.

This source changes one reader call from a single complete variant root to the
same variant plus the immutable frozen source root. The eleven global denied
capability probes and all byte, metadata and original-result checks remain exact.
The variant's source file mutation is still rejected against its original source
manifest. The case generator is never taken from an untrusted replacement.

The workflow downloads the exact prior complete ZIP, reads every ZIP/TAR object,
restores every logical file and directory, admits the original capture, prepares
the same six physical mutants and two relocations, then reads everything again.
All process limits are fixed before this recovery. No HIA or Rust target is
executed and no original process is replayed. The original failed run and its
complete partly prepared physical-control trees remain retained.

Unchanged regular files share immutable bytes during variant preparation and
restoration. Atomic replacement isolates every intentional mutation. Setup
changes to link counts and ctimes are declared; each quiescent reader proves
its entire actual before/after metadata and bytes unchanged.
