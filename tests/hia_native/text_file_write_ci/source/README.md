# Current target text_file_write source candidate

This isolated source candidate is based on target
`d3d75c30719db966b004756f610007a7c723729e` and installed HIA graph
`fa2aed97cf22b720d85bd8d08b720aeadba3c4d6`. It does not change the installed graph.

The parameter owner consumes the canonical root `Map<String, Value>` produced by
the actual `serde_json_span` map entry. It implements the exact target
`TextFileWriteMode` and `TextFileWriteParams` declarations, including the unit-enum
map representation and deny-unknown-fields diagnostics. The original declarations
are retained byte for byte in `reference/src/original.rs` beneath an observer-only
copyright and provenance header. `target/server.rs`, `target/Cargo.lock`, and
`target/text_file_write.rs` retain the complete exact target source bytes.

The author retains 35 old TextEditor parameter helper functions exactly and
relocates the existing diagnostic renderer without changing its body. The new
entry, field projection, enum values, declared-field errors and frame layout are
explicitly recorded in the composition proof. Source generation and AST equality
are source checks, not native compilation or semantic qualification.

The future body must follow this target's directory flock, no-follow opens,
metadata checks, bounded UTF-8 read, SHA-256 precondition, random exclusive stage,
file fsync, renameat2 and parent fsync. The older atomic_write component has a
different contract and is not substituted for this publisher. Successful calls
forget the target cache entry as the original does; they do not invent editor
history updates or a different file-lock policy.

This checkpoint has no native execution, Rust build, original comparison,
public registration, remote publishing, general asynchronous lifecycle or whole
runtime qualification. The shared checkout and all historical failure artifacts
remain unchanged. Future semantic execution is restricted to CI.
