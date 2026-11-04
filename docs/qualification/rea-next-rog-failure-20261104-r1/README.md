# Original ROG r1 failure evidence

This archive preserves an unsuccessful qualification. **qualified=false**.
The original all-features nextest run completed with 1,885 tests run:
1,879 passed, 6 failed, and 39 skipped. Its command exited 100; the
original durable wrapper job exited 1, without timeout or automatic retry.
No release binary was qualified or included.

The complete original integrated-build-r1 directory is preserved.
original-job contains the original request, stdin, lifecycle records and logs
as exact bytes. status-api.raw.json is the unparsed JSON text returned by the
authoritative process_status API after termination. request_digest binds the
original process_start identity and is distinct from the SHA-256 of a file.

source-snapshots contains the three unchanged test sources, checked against
the frozen before/after input manifest. failure-blocks.raw.log concatenates
six original failed-test output blocks; its index gives original line ranges
and hashes. Original full logs and before/after manifests remain authoritative.

The run used the ROG environment with /tmp on tmpfs. These results do not
replace the desktop ext4 evidence and are not a durability qualification.
The archive does not classify the causes of the failures, repair any input,
rerun tests, or include debug/release executables.

artifact-manifest.json hashes every other archived regular file. The outer
archive-pin JSON hashes the complete tar.xz and the artifact manifest.
