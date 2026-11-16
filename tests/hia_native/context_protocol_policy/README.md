# Resolved protocol feature qualification

This isolated recipe qualifies `context_protocol_policy.hepta` at the private
`Option<ProtocolVersion>` boundary. It compares the exact current target
`supports_cache_hints` and `allows_unsolicited_notifications` definitions from
`d3d75c30719db966b004756f610007a7c723729e`. The two original Rust definitions are
included byte for byte, after checking the complete retained `server.rs` source.

The reference uses the actual RMCP 3.9.0 `RequestContext`, a real
`serve_directly(..., None)` peer, and the real protocol metadata setter. Every
case asserts that `context.protocol_version()` equals its admitted resolved
input before invoking either unchanged function. The complete actual resolved
version is echoed to an independently retained stream. Protocol versions are
ordered as strings; this owner does not validate calendar dates or UTF-8. The
upstream typed decoder owns UTF-8 admission.

The fixed domain contains 1,480 resolved inputs and 1,941 actual HIA entries.
It includes None, the distinct empty string, all five declared SDK versions,
all threshold prefixes, every ASCII replacement at every threshold position,
Unicode and NUL insertions, unusual date-like strings and suffixes, and three
complete version values greater than 8 MiB. ABI controls include every bit of
the 32-byte header, all short headers, length overflows, None with a payload,
output capacities 0 through 33, dirty workspaces, and two interleaved owned
sessions. Each entry retains complete input, output and workspace before and
after, including all canaries and unchanged tails.

The native build uses the unchanged mainline build and loader scripts, the
fixed Hepta `d3e2c90173cf733e42b299d0c4274df4b593a12f`, an actual fresh B0/B1/B2/B3
development fixed point, `standalone=None`, and `serde-json.v1`. This is not a
new full cold-compiler qualification. The Cargo manifest and lock are copied
unchanged from the already retained current SDK context fixture. Rust 1.95.0
builds a fresh locked original executable only in CI. Complete crate archives,
actual registry file checksums, compiler Git objects/source closure, build
requests/receipts, and process input/stdout/stderr are retained.

Run the full recipe in its own new directory:

```sh
python -I -S -B tests/hia_native/context_protocol_policy/qualify.py \
  --phase all --source-root "$PWD" --hepta /path/to/pinned-Hepta \
  --output /path/to/new-output
```

Individual native and original replays have 60-second deadlines. The workflow
has a 15-minute job deadline. No failed domain is dropped or relabeled.

The complete capture is sealed before 16 actual reader mutations. These mutate
input, output, workspace, missing cases, source, native image/build output,
registry material, actual context observations and process custody. Two
independent physical copies are then verified in separate Python processes,
under write/process/native-mapping rejection guards. They cannot read the
producer capture. The source-bound guard is a regression check, not a sandbox
for arbitrary Python.

Verification of an existing complete result reads and compares existing files:

```sh
python -I -S -B tests/hia_native/context_protocol_policy/qualify.py \
  --phase verify --source-root "$PWD" --output /path/to/existing-output
```

This phase writes no reports and executes no native or Rust code. It checks
complete bytes, modes and source pins; its guard also verifies that the whole
retained tree's bytes, inodes, modification times and change times remain
unchanged. It rejects a missing original result instead of treating native-only
development evidence as final qualification.

Metadata-versus-peer protocol selection, authentication, the public route,
whole-runtime replacement, production activation and old-stack removal remain
outside this component's qualification. Their flags remain false.
