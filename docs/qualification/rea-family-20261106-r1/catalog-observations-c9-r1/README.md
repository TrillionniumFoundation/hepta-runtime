# C9 captured tool catalog identity

The captured original full-input/full-output tools/list has 229 tools. All 229 names in their original order, input schema fingerprints, output schema fingerprints and annotations match the frozen ledger. Raw tools and request/response frames remain in the sibling ELF observation archive. This is a contract identity check, not behavioral equivalence or completed P0 qualification.

The first read-only audit returned DIFF and exit 1 because it also required every source-declared native interface to be visible in the engine-free ELF session. It found 29 advertised native REA interfaces versus 34 in source. This original assessment and actual job output are retained unchanged.

The additive profile-scope.json records why that unconditional check differs: exactly the five rea_static_* routes are hidden by server.rs when rea_static_profiles is empty. The captured runtime configuration has no profiles; config.rs defaults that field to an empty map. There are no unexpected native interfaces. The fixed Ghidra runtime uses its own configured profile and actual observations.

Do not describe the source total of 34 as 34 newly added tools, 34 qualified replacements, or 34 advertised tools in this pure-Rust session. This continuation adds two interfaces. The replacement ledger remains 0/229 qualified.

The immutable original report pins source c9c79e27a2bf56bd204df6591ca2311dc872e317, source-tree e24bfd8dddb62f58b0bcfd6362c17b7ee7677605551f29a65fc98e44b847764f, native binary 56ae3b2313122ae7baae46df5536ee41f898aa09cbea10478a72de7cfe74e7cd and the complete original ELF family receipt f9507225345b65491cfb05f3a280eae2a9c04278b28d624035955efac24a1047.
