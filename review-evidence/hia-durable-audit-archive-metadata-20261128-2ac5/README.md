# Native audit v12 metadata read and recovery

This component preserves the original read_intent, read_anchor, and recover_metadata_link contracts in HIA. It keeps complete typed JSON parsing, private metadata checks, actual root and legacy binding, exact error order, and the original ten-field file stamp. A known complete hard-link remnant is removed only after all parsing and binding checks. Recovery scans the entire directory with strict UTF-8, then fsyncs the root and checks the final one-link state.

The HIA actor invokes the independently qualified typed archive-record HIA parser. Its HIA packer emits the fixed syscall engine. Production execution uses the actual emitted bytes and real openat, fstat, read, dup, getdents64, unlinkat, fsync, and close. The borrowed audit root is retained, and no Python filesystem callback or public raw descriptor is used. Pending typed children bind their complete input and block replay/destruction until acknowledged; all owned descriptors are closed on terminal failure.

## Actual qualification

- All 29 original archive-store methods passed in the fixed abc9ecb95ee9538518ec3f36c47b881974107021 Cargo graph. The original test bodies, assertions, release profile, default features, and complete Cargo.lock are unchanged. The new observer build took 199.184465 seconds. The original unit build and all 29 tests took 855.923727 seconds. All 360 registry archives, 315 actually used unit-test packages, 12271 source files, and 653 compiler artifact files were verified. The full original unit executable is retained.
- All 129 paired filesystem cases passed against that actual Rust observer. The comparison, including the 124 native boundary controls, took 16.460042 seconds. These are 124 unique controls, not 248 from counting the separate preliminary run twice.
- Cases cover complete object/sequence forms and escaped keys, exact size boundaries, malformed data, private modes, actual root/legacy mismatch, known and unknown hard-link aliases, nonregular files, invalid UTF-8, 4097 ignored directory entries with a final full scan, all 256 shards and neighboring counts, and refusal before any recovery.
- All 21 native-run source files were unchanged. Original requests/results, native traces, complete executable images and manifests, per-case filesystem observations, source captures, and actual failed authoring inputs are retained.
- The first author failed on the DSL's unsupported UnaryOp Not. Its complete original template and stderr are kept. The succeeding author expressed the same hexadecimal predicate with supported operations.
- Mode-000 files retain their real read refusal. FIFO and symbolic-link fixtures are only catalogued, not opened. Exact authored bytes, before/after observations, and readable originals are retained without permission changes.

The archive is content addressed. manifest.json maps every logical original to its full SHA-256, length, mode, and physical capture. Every object and every selected physical input was verified again before commit.

Metadata publication and shard initialization, the shared archive registry, redb, and the ten public Durable Requests handlers remain distinct ongoing work. Passing this component does not qualify those paths.
