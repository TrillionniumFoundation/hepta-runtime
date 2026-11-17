# Actual connection EOF capability

The fixed transport invokes global descriptor 55 with HRCNQ001, operation 3,
body length 0 and exactly 24 input bytes. Public JSON cannot choose this private
operation. Operations 1 and 2 retain their old input/output ABI.

Operation 3 requires the existing valid G2 workspace (at least 65536 bytes).
It returns HRCEOF01 followed by three u64 words: exit status, stderr offset,
stderr length. A settled connection returns 32 bytes, status 0 and empty span.
An unselected lifecycle returns status 1 and the exact SDK initialization error
at offset 32. The required complete output capacity is checked before writes.

The mode is read from the actual persistent G2 state. Missing metadata and an
unsupported inline version during the opener reply and retain that opener.
Ping and bootstrap discover do not select a lifecycle. A valid initialize
selects the legacy lifecycle immediately after its response.

The host first drains the existing task registry and closes stdout, then invokes
this capability. It checks the complete descriptor and writes only its returned
stderr span, including short writes/EINTR/EAGAIN. It stores the admitted status
at the newly reserved parent configuration context word 920, completes all
existing HIA config cleanup, and exits with that status. The host does not parse
JSON or determine SDK policy.
