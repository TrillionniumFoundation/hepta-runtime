# Actual WAIT capture recovery and allocation identity

This package executes no original or HIA application. The exact 24 original
and 24 native process captures remain unchanged, including three producer
FAIL results. The unchanged base reader still validates every complete wire,
file, lock, cache, history, Scope/context buffer and Drop boundary.

An inode number is an allocation address rather than an immortal object ID.
The only additional comparison path proves two real serial replacements:
two distinct request contexts each retain full HIA atomic state, their consumed
successful rename acknowledgment, empty read-FD ownership and closed temporary
FD. The immutable native syscall gate and HIA owner are included in full.
The first context retires before the second resumes. The temporary entry is
absent at initial and retained observation barriers, there are no other
mutating fixture actors, target link count is one, every other object stays
identical, and the final observation follows the real settled-lock barrier.

Only after these conditions hold does the reader assign a fresh lifetime to
the recycled native numeric dev/ino pair. All raw metadata is retained. The
entire resulting identity relation must equal the original; no identity field
is ignored. This is deliberately restricted to the observed two-replacement
domain. A different or unproved mismatch remains a failure.

Eight physical controls and two complete relocations use the same original
control implementation with only its reader import changed. Five additional
physical semantic controls reseal deliberately corrupted observed rename/FD
bytes so that the lifetime preconditions themselves must reject. The
production binary and all application inputs are unchanged. Each application
budget remains 60/180 seconds, and each CI job remains 15 minutes.
