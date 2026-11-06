# Execution input source binding regression

The previous `Selection` fingerprinted native source, tests and scripts, but
omitted deploy helpers, runtime configuration, worker code, non-Rust vendor data,
host tools, server metadata and the reference files below `docs/rea-native`.
Changing those files could preserve the advertised source digest. Restoring the
original bytes also escaped the earlier monitor's selected-file predicate.

The revised `hepta.rea.execution-inputs.v2` selection includes those execution
inputs and the four frozen REA reference/mapping files. Output/cache locations
cannot hide selected input roots or reference ancestors. Generated ledgers,
qualification receipts and ordinary prose remain outside the selection.

`red.json` and `green.json` record exact commands, source/test hashes, real process
exit codes and raw output hashes. The same final eight-test suite runs against
the archived earlier producer and the revised producer. Its temporary files and
Linux inotify observers are real; no Rust compiler or engine is simulated or
qualified by these checks. The unchanged 22-test independent build-consumer suite
also passes on the revised desktop candidate (durable job receipt retained by the
combined run). Source change detection remains a local, trusted-operator contract.
External engine/toolchain/cache identities need their own execution observations.
