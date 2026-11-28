# Public native binary_write qualification

The default stdio MCP executable now routes `binary_write` through the existing
typed request and policy plan, an HIA jobs-audit owner, the owned SSH operation,
and the native binary writer. The audit append must succeed before SSH starts.
The original create-only/version checks, strict Base64 decoding, atomic file
replacement, metadata preservation and hard-link refusal are retained.

`QUALIFICATION.json` binds the exact source closure, executable, complete raw
evidence and component qualifications. The public route passed on ROG through
an owned OpenSSH server with its real authentication, pipes and processes.

## Executed artifact

| Item | Result |
| --- | --- |
| Source inputs | 1,062 files |
| Source binding SHA-256 | `2e02569c77e019ae707719680e3d17dd05955fa3a2e2e25024bcb26b955a11ae` |
| Compiler commit | `d3e2c90173cf733e42b299d0c4274df4b593a12f` |
| Qualified B3 image SHA-256 | `bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0` |
| HIA image instances | 175, including 130 direct members |
| Physical images / selectors | 133 / 83 |
| Complete public executable | 36,986,880 bytes |
| Executable SHA-256 | `773c5a8101e17ae576000260bc8687ef33f242d6bf6b9e34709c431be9b4e3ff` |

The final default builder completed in 64.945 seconds. It validated all 130
reused direct members against their actual source, native images, compiler and
buffer profiles, built the eight worker members and the I/O and catalog
dependencies, and executed the original HIA linker and packer. Every executable
byte equals the development candidate that passed the local business and
lifecycle tests. `default-build.json` and `default-byte-identity.json` retain
the original records.

The assembler portability repairs retain the original object and full-ELF
checks for SSH, file-info and multi-read. Explicit original padding and section
order reproduce the qualified artifacts; their pins were not relaxed.

## Runtime evidence

| Gate | Executed result |
| --- | --- |
| Native writer versus complete original Python helpers | 44 filesystem cases, 88 actual executions |
| Native strict Base64 versus CPython 3.14 | 20,058 complete result comparisons and 5 capacity cases |
| Native audit append/namespace versus original Rust | 165 cases across 5 profiles, including real strace sync-count comparisons |
| Default MCP over real OpenSSH | 26 business cases; 17 actual SSH invocations and 15 audit events |
| Default MCP lifecycle over real OpenSSH | 3 cases with actual process identity and reaping observations |

The public cases cover empty/all-byte/1 MiB writes, Unicode and quoted paths,
replacement metadata, stale and missing versions, create-only collisions,
strict Base64 errors, missing parents, embedded NUL, hard links, typed request
refusals, write policy and path bounds. A real audit-file hard link makes the
audit append fail; no SSH invocation or target write occurs. Removing the
condition permits a subsequent write. Existing `file_info` and `binary_read`
results are checked on the same executable.

The lifecycle gate holds a real installed writer in a blocked read. Ordinary
cancellation retains that operation and discards its response; EOF drops and
reaps an incomplete writer after the existing drain policy; the original
30-second deadline terminates the operation without automatic retry and the
next request succeeds. The exact original eleven SSH arguments are retained;
the fixture adds only its private OpenSSH client configuration.

`complete-rog-evidence.tar.xz` contains all 105 evidence members, including the
full request/response wires, original helper frames, SSH arguments and server
logs, observed process identities, manifests and fixture controls. All 103
regular file records were independently hash-verified after retrieval; FIFO
metadata and the index are retained. `complete-helper-evidence.tar.xz` retains
all 446 standalone helper files plus their index. The audit component's full
165-case archive is in `qualification/jobs_audit_append/v1/`.

The build manifest records build results. The combined runtime qualification
for this exact artifact is `QUALIFICATION.json`, which requires both public
runtime phases and the component evidence. Whole-runtime replacement, all 136
routes, an independent full cold build, production activation and old-stack
removal remain unqualified.

## Reproduction

Run the default builder from this checkout using CPython 3.14, the exact
compiler checkout and a verified B3 bootstrap directory. An output directory
must be fresh. Omitting `--reuse-manifests` compiles all direct members.

```sh
python3.14 -I -B scripts/hia_native_runtime_mcp_build.py \
  --source "$PWD" --hepta /path/to/Hepta-d3e2 \
  --bootstrap /path/to/verified-bootstrap --output /path/to/fresh-build

python3.14 -I -B tests/hia_native/public_binary_write/run.py \
  --manifest /path/to/fresh-build/build/public-task-batch-extract/manifest.json \
  --source "$PWD" --reference-python /path/to/python3.14 \
  --output /path/to/fresh-business --transport loopback

python3.14 -I -B tests/hia_native/public_binary_write/lifecycle.py \
  --manifest /path/to/fresh-build/build/public-task-batch-extract/manifest.json \
  --source "$PWD" --business-evidence /path/to/fresh-business \
  --output /path/to/fresh-lifecycle --transport loopback
```

The network gates require an actual OpenSSH client/server and the Linux
facilities used by the original fixture. They fail if those facilities are
unavailable. The ROG execution used CPython 3.14.4; standalone local comparison
and the final build used CPython 3.14.10.

## Source and history custody

The integration keeps normal merge parents for public baseline
`472204becc65f41056d452712320c8565db18efd`, PR 165 at
`7a4a46d89abbe1036c0f7e5561c318c8a05206f5`, and PR 167 at
`5471636345427896f13ef106aaa3b361564b69f4`. The retained inverse source view
continues to verify every original input before building the extension.

A complete 1,715-member recovery archive preserves all 1,062 actual inputs,
authors, test controls, B3, candidate, local evidence and the two real merge
commits. It was committed, expanded and checked on AI395 at
`/home/qq/hia-runtime-writer-recovery-63dc-v1/`; the SHA-256 is
`d26567db3436f06ab94503ccd3fd7f4cf360d461ac28b0b7f56e695acc2adbe8`.
The exact ROG input package and executed program remain at
`/home/qian-qi/hia-runtime-public175-63dc-v1/`. Source-preservation and runtime
evidence are separate records so the later successful default build and real
SSH execution do not retroactively alter earlier evidence.
