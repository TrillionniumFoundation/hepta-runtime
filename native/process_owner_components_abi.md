# Process owner native components

This change provides four independent HIA components for the nine process
interfaces. It does not install a public process router or claim a completed
remote lifecycle.

| Component | Private request | Responsibility |
| --- | --- | --- |
| process_params | HPRPAQ01 | Nine original parameter schemas, defaults, field errors and exact typed arguments |
| process_validation | HPRVLQ01 | Execution, path, environment and resource policy over captured typed arguments and installed HRCFTR01 host bytes |
| process_identity | HPRIDQ01 | Complete original ProcessStart request binding, canonical field order and native SHA256 |
| process_record | HPRJRQ01 | Original 17-field durable JobRecord, exact u128 creation time, compact bytes, owned typed arena and pretty bytes |

The records and field definitions remain derived from the exact original
Rust sources. The HIA functions perform parsing, policy and serialization.
Rust programs in authoring and archived preparations are qualification
oracles. The HIA author sources execute captured dependency bytes and check
the physical inputs again before completion. The final four source images
reproduce the already executed HIA bytes exactly.

JobRecord accepts a maximum of 4 MiB of raw JSON and preserves the existing
4 MiB durable pretty-output limit. The growable native test session retains
the original 12-round limit, 128 MiB output limit and 256 MiB workspace
limit. The first exact-size allocation attempt failed within that limit;
the successful successor rounds each requested allocation upward to a power
of two without increasing any limit. All failure and success inputs remain
in the archive.

The large-boundary capture's original index accidentally reused a loop
variable for its last eleven offsets. An independent reader verified all
99 complete native frames (1,901,223,016 uncompressed bytes), their headers,
input/output/workspace hashes and canaries. It wrote a separate corrected
index and retained the original index, raw stream and report unchanged.
This data-only readback did not rerun the native product.

The exact component results and archives are in the evidence directory
docs/evidence/process-owner-components/20261128-2ac5. The 747 native original
files were checked byte for byte and by mode on Desktop and again on Mac.
The separate author/reference archive preserves the named original
preparations, failed author attempts, replay inputs and two original
reference executables.

Pending integration includes descriptor-bound durable JobRecord IO,
pending/dispatch/outcome lifecycle transitions, installed op10/op11
capability binding, real SSH execution and all nine original public
interfaces. File op12 does not authorize process roles. No shared router,
global selector, original Rust implementation or original test body is
changed by these components.
