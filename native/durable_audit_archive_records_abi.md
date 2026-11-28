# Audit archive typed metadata

This module parses the original `ArchiveAnchor`, `ShardAnchor`, and
`InitIntent` types from `abc9ecb95ee9538518ec3f36c47b881974107021`.
It is the typed-data layer used by the archive owners. Descriptor admission,
root and inode bindings, format 12 policy, initialization recovery, and the
redb index have their own owners and qualification.

## Input

The six-argument native HIA ABI receives a complete byte frame:

| Offset | Meaning |
| --- | --- |
| 0 | `HRAATQ01` |
| 8 | Unsigned kind: 1 legacy anchor, 2 shard anchor, 3 initialization intent |
| 16 | Unsigned raw JSON byte length |
| 24 | Zero |
| 32 | Complete original JSON bytes |

The complete length must be exactly 32 plus the declared raw length.
Legacy raw bytes retain the original 2,048-byte file-read bound. The two v12
metadata types retain the original 65,536-byte bound. These are file-read
bounds; the JSON parser does not impose a 256-element vector policy.

The original struct deserializer accepts either its object form or its
fixed-length sequence form. Unknown and duplicate object fields are refused.
Escaped keys are decoded before identification. The four legacy fields and all
identity limbs are exact unsigned 64-bit numbers. The v12 format field is an
unsigned 32-bit number. The optional initialization archive identity can be
null or omitted in object form. Its position remains required in sequence
form. The original whitespace, numeric grammar, array length, and trailing
byte rules are preserved.

## Output

A typed refusal occupies 32 bytes: `HRAATR01`, diagnostic 1 for a type/JSON
refusal or 2 for the original raw-file bound, followed by two zero words.

A successful response is 128 bytes plus 16 bytes per shard identity:

| Offset | Meaning |
| --- | --- |
| 0 | `HRAATR01` |
| 8 | Zero diagnostic |
| 16 | Input kind |
| 24 | Complete output byte length |
| 32 | v12 format; zero for legacy |
| 40, 48 | Root device and inode |
| 56, 64 | Legacy archive device and inode |
| 72 | Archive identity present: 0 or 1 |
| 80, 88 | Archive device and inode; zero when absent |
| 96 | Shard identity count |
| 104–127 | Zero |
| 128 onward | Complete shard identities, two unsigned 64-bit limbs each |

For kind 1, the original `archive_device` and `archive_inode` occupy the
legacy pair. The optional archive pair and shard count are zero. The parser
does not claim that any identity matches a real directory.

Malformed framing returns `0xffffffff` before output publication. Insufficient
workspace or output returns `0xfffffffe`. Workspace must hold
`512 + 4 * raw_json_bytes`; the maximum required workspace is 262,656 bytes.
Successful output capacity is checked against the complete parsed vector.
Capacity refusal never publishes a partial response.

## Actual qualification

The original three derives were reached with append-only observation functions
inside the complete, unchanged original Cargo dependency graph and release
profile. The original 360 locked registry archives and all 309 actually used
registry packages were rechecked; the original default features were retained.
The reference observes raw JSON slices directly rather than pre-parsed JSON
values.

Actual native compilation and the original reference agreed on all 3,024
inputs. Another 45 native controls cover framing, exact capacity, and refusal
without partial output. Inputs include shuffled and escaped keys, duplicate
nullable fields, the complete integer boundaries, byte mutations, file-size
edges, and shard vectors both below and above 256 entries. The successful
native whole source is 86,216 bytes with SHA256
`729c1b695584bc88a36bbbde7cdb0c1069743c1b355e189e14e55b74da4b3ec0`.

This qualification is a component result. Public archive routing, descriptor
lifecycle, v12 directory recovery, and the redb transaction graph are measured
separately.
