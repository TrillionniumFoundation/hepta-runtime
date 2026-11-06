# Native operation custody

These files preserve the explicit qualification, control materialization, CI,
holder, and evidence-capture operations associated with R36. Benchmark outcome
flags remain those reported by the original campaigns. A successful control or
capture operation does not imply that the candidate passed its performance gates.

`raw-mcp/` contains the exact JSON text returned by the connector for the named
operations; no JSON parse/serialize round trip was used for those file bodies.
Use this text for large integer fields such as request fingerprints. Neighboring
formatted JSON files are convenient response views and may normalize number
representations. The byte-exact remote report and log files are retained under
`performance/`, `holder-originals/`, qualification/CI directories, and the evidence
archive, with their independently observed sizes and SHA-256 identities.

Native terminal evidence requires the terminal state and exit code, complete and
durable output, confirmed terminal publication, synced and untruncated logs, and
matching seen/stored byte counts. A read reaching EOF alone is not used to infer
process completion. The lifecycle holder's original `failed / 1` result is kept.

The original evidence-tool installer attempt 01 failed with `KeyError: payloads`
before writes because the package manifest uses `files`. The corrected installer
operation 02 kept the same package bytes. The first evidence capture separately
failed in its scan phase on repeated telemetry queue bounds. Both operational
failures are retained and are not hidden within the zero-retry benchmark counts.
