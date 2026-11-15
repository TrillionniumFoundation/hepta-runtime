# Desktop r1 original partial matrix

**qualified=false.** The original durable job timed out with exit 124 after
34 of 35 commands completed with their expected exit codes. The final release
command had started but did not finish. No target release was read or archived;
there is no qualified binary in this evidence.

Original request/stdin/lifecycle/exit/witness/stdout/stderr bytes are preserved
under original-job. The complete original integrated-build-r1 directory,
including the unfinished release log, is preserved without rewriting records.
The original inputs-after.json and qualification.json are absent. No replacements
were generated under those names.

terminal-observed-inputs.json is explicitly an independent observation after the
original job terminated. It invokes the unchanged inventory(root) function from
the hash-verified original f7 runner declarations, without executing the runner's
plan or commands. It matched all original 295 source and 613 verification entries.
It is not a runner-produced after snapshot. Three original test sources were
sealed before the root applied any later fixture changes.

The original desktop Rust summaries are 1,885 passed / 39 skipped / 13 slow for
all-features and 1,860 passed / 27 skipped / 5 slow for no-default-features.
The 21 original Python unittest suites report 441 passed, zero skipped, zero
expected failures, and zero unexpected successes. These are unittest results;
no pytest xfail field is invented. test-counts.json preserves every exact log
summary, line number, count, and original log SHA-256.

The ledger strict-open check returned its expected code 3. This preserves open
upstream parity gates and does not claim full REA parity. The desktop physical
filesystem evidence is kept separate from ROG tmpfs functional runs. A separate
post-terminal findmnt observation is included and is not portrayed as an original
runner receipt.

artifact-manifest.json binds every other archived regular file. The outside
archive-pin JSON binds the complete tar.xz and the artifact manifest.
