# Interrupted archive experiment r01: preserved, not evaluated

The run was deliberately cancelled. Its native job ended cancelled with exit
-15 and complete captured output; it did not hit its outer timeout. Root
reported the decision as based only on absolute completion rate: 74 of 536
cells after about 30 minutes against a 90-minute budget. That earlier decision
snapshot is distinct from the later preservation inventory of 81 complete
cell receipts. No relative performance is computed or selected here.

The complete evidence bundle preserves every original file's parsed JSON,
every JSONL record, and every text-log line, including original newline
information. It contains all 102 archive members plus the separate fixed-
version transfer/status proof. Original byte hashes are retained. The raw
archive itself is private and is not a publication artifact.

There are 81 complete cell receipts: twelve warmups and 69 measured cells,
containing 9,216 query rows. The original stdout streams retain 9,256 query
rows: the extra forty belong to cell-0081, which has a start but no completion
record. Zero failed query rows were observed. This does not certify unrecorded
requests or the eventual result of unfinished work. Cell receipts repeat
stdout rows and must not be added to the stdout total. Only the 16,384-record
fixture's A/B streams are present; no 65,536-record fixture start is observed.
The coverage file retains all 536 planned cells without performance ranking.

No final series.json, inputs-after receipt, finalized sampler result, final
original-fixture hash verification, or per-child graceful-drain witness is
present. The two observed resource-error JSONL rows remain complete records,
but they are not a finalized whole-run sampling report. Native output_complete
and the systemd observation cannot supply the missing experiment/child
completion proofs. No fixture was deleted or relaunched for publication.

Every query row, cell event, cell check, cell specification and both recorded
resource snapshots are compared directly with their public counterparts.
Absolute latency, CPU and resource values remain in the
complete record without calculating relative gains, evaluating gates, or
adopting a candidate. The frozen full-scale plan remains unchanged. This
interruption is neither a performance win nor proof of a correctness failure.

The frozen A26 sanitizer supplies all string and opaque-value transformations.
Explicit context handles identity/stamp fields, job IDs, fixed file versions,
loadavg's final PID token and collision-safe opaque dictionary keys. Numeric
readable_fields.identity coverage counters would remain numeric, if present.
The fixed integer keys bytes (with a SHA-256 receipt) and errno (in a resource
error row) retain their schema names: Cargo crate names otherwise cause the
unchanged generic user-discovery rule to obscure these technical labels.
All such adaptations are listed in the complete redaction inventory. The first
local publication attempt is retained unchanged and is not for publication;
this r02 corrects only that schema-label issue, without rerunning the experiment.
Credential
or raw response fields use hash receipts; they are never decoded for public
exposure. No input, frozen package, runtime, or remote host is modified.
