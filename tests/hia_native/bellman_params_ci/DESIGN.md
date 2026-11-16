# Bellman typed parameter owner

This owner implements the unchanged `BellmanPlanParams` Deserialize contract at
target `d3d75c30719db966b004756f610007a7c723729e`. Its input is the complete
canonical JSON produced by the already qualified serde_json Value owner. It
does not decide solver limits, worker admission, deadlines or authority.

The whole input is typed before emitting HIABELL1. Counts outside 1..4096 retain
the real state count in a 16-byte graph; counts inside that domain retain all six
actions. Continuations retain their true branch count and the first three branch
records. Every remaining state and branch is still deserialized, so a later
typed error cannot be hidden by an earlier solver limit. The numerical owner
checks those limits before reading the compact records.

Both map and sequence forms of derived structs are supported. Internally tagged
actions accept the original sequence form as well as maps. Map fields arrive in
serde_json Value order. Unknown fields, missing fields, array lengths, integer
range checks and error precedence follow serde 1.0.229/serde_json 1.0.151.

Two independently compiled HIA modules keep the compiler's existing function,
block and instruction limits: a typed tree projection and a complete diagnostic
renderer. The latter reuses the qualified Unicode Debug table and finite f64
formatter. Neither module delegates decisions or floating-point conversion to
Python or Rust. Rust is an unchanged-type reference executed only in CI.

The parser uses an explicit dynamically sized stack, rather than the lexical
JSON recursion limit: RawValue expansion can create a canonical Value deeper
than the original text parser's per-deserializer depth limit. Private input is
bounded by the existing 512 MiB private batch-plan buffer profile, allowing
the upstream Value owner's complete canonical expansion. Output publication is atomic;
capacity requests and invalid frames are separate from typed user errors.

All whole-runtime and public-handler qualification claims remain false until
the real Value owner, typed owner, worker, clock, commitment and result renderer
are composed and compared through the public route.
