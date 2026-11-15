# Durable guarded patch journal: isolated implementation plan

The journal wraps one existing fixed-request Rust guard. It does not search
weights, deploy candidates, alter live pointers or run background recovery.
The original source remains unchanged; all candidates and restorations are
immutable artifacts in the existing artifact store.

The complete typed request, canonical state directory and ordered canonical
workspace roots are bound to an explicit semantics version and a named source
fingerprint. The fingerprint covers guard, exact norm, forward, tensor,
artifact, relevant REA parsing/access modules, this journal and Cargo files.
It is not a claim that those sources cover the entire compiler/OS/dependency
execution closure. The canonical envelope is at most 1 MiB.

A separate weight-guard-journal-v1 directory uses owned 0700 directories,
owned 0600 single-link files, component-wise O_NOFOLLOW opens, a directory
flock spanning evaluation, descriptor-relative publication, exclusive
renameat2, and file/directory fsync. Count and byte quotas include abandoned
staging data. Retention has no silent eviction or overwrite. Model artifacts
keep their independent quota and authentication.

The ordinary sequence is durable intent, existing complete guard execution,
candidate reference, durable completion, then returned result. An interrupted
same-request reconcile repeats the full guard before forced inverse
publication. This preserves the current L2/labels/source admission order.
It may create an isolated candidate if the process died before applying one;
the added work is reported. Any recovery result has accepted=false.

A completed entry is never an acceptance cache. A retry reruns the complete
guard and authenticates current source/candidate bytes, then compares all
recorded semantics except operation time and idempotent-reuse display flags.
Completed interruption recovery repeats the forced restore and can never
become acceptance. Source loss, tampering, quota failure and errors leave
explicit rejection/unverified outcomes. The first failure can be retained
immutably without pretending that every attempted retry has a durable receipt.

Tests use real isolated native files and an owned subprocess. The parent
waits for a test-only phase marker, sends SIGKILL, waits for death, and starts
a fresh process to reconcile the exact request. Planned boundaries are after
intent, after guard/artifact publication before candidate logging, after
candidate logging before completion, and after durable completion. Additional
tests cover private file security, quota, exclusive publication/concurrency,
full request binding, semantic drift, changed/missing source, and changed
accepted artifacts. Failpoints exist only in cfg(test) builds.

Existing guard/server/module registry files are not edited in the frozen
trust-region worktree. Integration and compilation use a separate checkout.
