# Native APK signature-record verification

## Accepted finite contract

`rea_inspect_apk_signature` reads one policy-admitted APK and verifies the mathematical self-consistency of its supported v2/v3 signature records. It binds the reported full-file SHA-256, declared APK content digest, signed-data bytes, signature, public-key bytes and exact leaf-certificate subjectPublicKeyInfo to the same captured archive. The native module uses the existing pinned `ring` and `sha2` dependencies. No Java, Android SDK, OpenSSL, Node or REA process is required in the production path.

The result format is `hepta.rea-apk-signature.v1`. Its independent signer IDs are `apksig-v1:<complete-archive-sha256>:<scheme>:<ordinal>`. `rea_evidence_compatible` and `complete_android_verification` are always false. This is a qualified native sub-contract; it does not close the complete original REA Evidence/analysis-view contract or Android package-verification contract.

## Interpretation of results

| Field/state | Meaning |
| --- | --- |
| `verification.scope` | `supported_signature_records_and_content_digests_only` |
| `v2_v3_records: verified` | Every declared supported signature record has a matching APK content digest, a valid signature and exact leaf-certificate SPKI binding; known structural consistency checks passed. |
| `v2_v3_records: invalid` | At least one known signature, content digest, public-key binding, SDK copy or supported stripping-protection requirement failed. |
| `v2_v3_records: partial` | At least one declared record or stripping requirement cannot be verified by this finite implementation, with no known failure. |
| `v2_v3_records: absent` | No v2/v3 signer records were present. It says nothing about the validity of other schemes. |
| Tool error | The source was not admitted, changed, exceeded a budget, or contained an invalid/unsupported structural envelope. No success report is returned. |

No result establishes Android installability, trusted signer identity, validity dates, issuer signatures, chain trust, revocation, app manifest semantics or code safety. The response states these limits at both the verification and signer levels. Android evaluates scheme/SDK selection and signature algorithm preference differently: this tool checks **every declared supported record**, so its record verdict is deliberately not an Android platform verdict.

## Implemented checks

- A unique classic ZIP end record ending at EOF; single-volume and bounded directory count/extent; central/local name, flag, method and payload-extent consistency; signing block must not overlap local payloads.
- Matching signing-block size headers, exact pair extents, unique pair IDs, bounded nested length fields, signers, certificates, algorithms and attributes.
- Correct APK 1 MiB chunked SHA-256 and SHA-512 over the prefix, central directory, and end record with its central-directory offset rewritten to the signing-block start. ZIP comments and section boundaries are included.
- Exact digest/signature algorithm-list agreement; duplicates are rejected.
- RSA-PSS SHA-256 and SHA-512, RSA PKCS#1 v1.5 SHA-256 and SHA-512, with RSA 2048–8192-bit keys and odd public exponent in `3..2^33-1`; ECDSA SHA-256 on P-256/P-384 using ASN.1 signatures. PSS uses digest-length salt, as required by these APK algorithm IDs.
- Bounded DER-envelope parsing and exact leaf-certificate SPKI binding. The DER parser does not claim complete X.509 semantic validation.
- Identical signed/outer v3 SDK ranges with minimum no greater than maximum. SDK-specific signer selection remains unevaluated.
- v2 stripping-protection attribute `0xbeeff00d` with requirement 3 must have a v3 block; unknown requirement values remain partial.
- Reserved trailing signed-data bytes are retained by length/hash and covered by signature verification. Modern Android v2 fixtures contain four such zero bytes.

v1/JAR signature markers are detected but JAR signatures and per-entry coverage are unverified. v3.1 (`0x1b93ad61`), v3.2 (`0x70e1c89f`), proof-of-rotation, source stamps and external v4 `.idsig` remain explicitly unverified. Unknown block IDs are retained as ID/length/hash observations. DSA, ECDSA SHA-512, verity digests and unknown signature algorithms are unsupported and cannot yield a fully verified native record set. A v3.1/v3.2 block without an examined rotation attribute is reported as newer-scheme lineage not examined, rather than lineage absent.

## Admission and isolation

The controller uses `rea_files::open_confined` for existing configured controller workspace roots. It captures bytes through one descriptor, checks ordinary concurrent changes using before/after metadata, and optionally checks the caller's complete lowercase SHA-256 before invoking the worker. It never reopens the source path in the parser. The metadata checks do not defend against privileged races which restore metadata; source identity always refers to the complete captured sequence.

Capture cancellation and its thirty-second checks are cooperative between regular-file reads. They do not interrupt a blocked filesystem read or establish a hard end-to-end capture deadline. The current MCP path forwards cancellation through the handler token and does not abort the handler on ordinary cancellation or transport EOF. Direct Rust callers that abort or drop this public async future during file I/O are outside the qualified lifecycle contract: an already running Tokio blocking read can outlive the caller. The six public-MCP lifecycle gates cover the worker stage after capture, not stalled-filesystem reads or runtime shutdown during stalled I/O.

Production parsing runs in the stdin-only `rea-apk-signature-worker` with no source path, runtime credentials or inherited environment. The worker sets resource limits and, on Linux, parent-death binding and the existing post-read seccomp policy. The controller enforces cancellation and an independent wall deadline, then explicitly kills and reaps the child on failure. No APK is installed, executed, extracted, fetched or modified.

| Budget | Bound |
| --- | --- |
| Complete archive | 128 MiB |
| Signing block | 16 MiB |
| ZIP entries | 50,000 |
| Block ID pairs | 128 |
| Signers per v2/v3 block | 32 |
| Certificates per signer | 8 |
| Certificate / SPKI | 64 KiB |
| Algorithm records per signer | 32 |
| Additional attributes per signer | 64 |
| Worker CPU / wall deadline | 20 s / 30 s |
| Worker address space | 1 GiB |
| Worker open descriptors | 64 |
| Response | 1 MiB |
| Concurrent controller inspections | No runtime count ceiling; see [concurrent execution](../CONCURRENCY_POLICY.md) |

The current complete APK static Evidence path retains its per-input parser
limits, including signer, certificate, attribute and output counts. Its
`capacity` error action now directs the caller to select an input within the
reported parser bounds; it no longer instructs the caller to wait for another
analysis. This is one explicit current response-text difference from the
frozen `service-errors-r1.json` capture. The regression keeps that historical
file byte-for-byte and compares every other error field exactly. The change
does not requalify the historical APK run or close any REA compatibility row.

## Independent producers and oracle coverage

`tests/fixtures/rea_apk_signature/provenance.json` records every public fixture's actual hash, size, Android verification output and independently computed Python `hashlib` content digests. All keys were generated exclusively for these tests; private keys are excluded from the repository. The generator copies the existing owned `rea_application/owned-aapt.apk` seed.

Nineteen positive fixtures cover real Android v2, v2/v3, ECDSA, v1-only, mixed v1/v2/v3, multiple signers, rotation for v3 and v3.1, more than two 1 MiB content chunks, and a ZIP comment. Independent byte encoding plus OpenSSL signing generates all four supported RSA algorithm IDs and ECDSA P-384/SHA-256; Valid P-521/SHA-512, RSA-1024 and RSA with 34-bit public exponent (`8589934593`) fixtures prove unsupported algorithms and key parameters are explicitly partial. The 34-bit-exponent fixture is accepted by Android and caught a pre-fix classification bug: ring rejected the unsupported key and the native record had incorrectly said `invalid`. An independent reviewer reproduced it with a second 34-bit exponent (`8589934609`); that public fixture is retained byte-identically. The supported upper-bound exponent (`8589934591`, 33 bits) is a positive native-verification case. The parser now classifies the documented ring exponent range before attempting the cryptographic verification. Every positive is checked by the actual Android `apksigner` verifier.

The negative `forged-matching-digest.apk` changes the payload and updates the declared chunked digest while retaining the original signature. Original REA reports `matches_apk: true`; Android and the native signature verifier reject the signed-data signature. This distinguishes content-digest equality from signature verification.

`qualify_apk_signature_native.py` runs the actual compiled worker, the installed original `rea-agents` 6.8.0 provider, and Android `apksigner` across all twenty fixtures. It compares exact source identity, scheme signer counts, leaf-certificate SHA-256 fingerprints, public-key lengths, signed-tail lengths, algorithm IDs, declared digest values, digest equality, v3 SDK ranges and v3.1 presence. It independently recomputes both supported content digests and sends malformed inputs through the real worker process. The qualification JSON retains the native binary hash, original producer identity, field comparisons and actual oracle diagnostics.

Original producer identity: frozen source `morluto/rea@93b8b82db70279e40f484114cff9dc1958dc14ee`; installed `rea-agents` 6.8.0 tarball SHA-256 `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`. The qualification script hashes that actual tarball and compares every installed package file with its tar member before running the original provider. A package version alone is not a moving-upstream compatibility claim.

The host's standard JDK lacks the `SHA256withRSA/PSS` alias expected by Android's verifier. The qualification helper registers the already installed Bouncy Castle 1.77 provider using `Security.addProvider`, then calls the unmodified `com.android.apksigner.ApkSignerTool`. This supplies the missing standard cryptographic provider; the APK parsing and verification oracle remains Android's implementation. This helper is test-only and is not a runtime dependency.

### Accepted native build

The accepted implementation checkpoint is `ad5eae44dae08b3dbf25c88d653702374e2daea3`. The [native qualification receipt](validation/apk-signature-native.json) binds the tested binary SHA-256 `01ff4fc0127dda50f3a18a1901f77e43f900076a1cbcc32c888e76d7e0645157`, hashes of all four native source modules, the original REA provider and tarball, Android verifier JAR, Bouncy Castle provider and Java runtime.

The 2026-11-04 run passed fourteen native test functions, nineteen Android-verified positive fixtures, the forged matching-digest negative, and four malformed inputs through the real compiled worker. The REA preflight compared all 2,398 installed package files byte-for-byte with the pinned tarball before running its provider. The fixture comparison checks independently computed chunked SHA-256/SHA-512, source identity, signer order and count, certificate/SPKI facts, algorithm lists and v3 SDK copies.

The final Rust test run used the package-only test-profile override below to reduce compile time. The production binary used the repository's unchanged development profile. Formatting and all-feature/all-target Clippy with warnings denied also passed.

```sh
cargo +1.95.0 test --all-features --locked --offline -j2 \
  --config profile.test.package.hepta-runtime.opt-level=0 \
  --lib rea_apk_signature::tests
cargo +1.95.0 build --all-features --locked --offline -j2
cargo +1.95.0 clippy --all-features --all-targets --locked --offline -j2 -- -D warnings
cargo +1.95.0 fmt --all -- --check
```

Independent public-MCP review repeated its unchanged script SHA-256 `633dd05e70696b5082f6d5f092e02a56f50ed5d43d7faf8b4ba64ff4105b1bbf` against the same frozen binary. Its six gates passed: cancellation in approximately 0.022 seconds under the fixed five-second observation limit; the production thirty-second worker deadline in approximately 30.072 seconds; original-owner termination and reaping; successful subsequent requests; and a fresh controller restart. Both controllers exited with code zero after stdin EOF, with no manual cleanup counted as a pass. The independent reviewer separately retested its exact 34-bit-exponent counterexample against this binary: the signature is explicitly unsupported while content digest and leaf SPKI still match. This review qualifies lifecycle behavior and the repaired classification; it does not widen the finite cryptographic contract.

### Reproduction

Use an empty scratch directory for generation, because it creates fresh disposable signing keys. Generated APK bytes vary with keys/signatures; committed provenance pins the exact accepted fixture bytes.

```sh
python3 scripts/generate_apk_signature_fixtures.py \
  --apksigner /opt/android-sdk/build-tools/35.0.1/apksigner \
  --bc-provider /usr/share/java/bcprov.jar \
  --seed tests/fixtures/rea_application/owned-aapt.apk \
  --output tests/fixtures/rea_apk_signature \
  --scratch /absolute/empty/test-key-directory

cargo +1.95.0 test --all-features --locked --offline -j2 --lib rea_apk_signature::tests

python3 scripts/qualify_apk_signature_native.py \
  --binary /absolute/path/to/hepta-runtime \
  --rea-install /absolute/path/to/node_modules/rea-agents \
  --rea-tarball /absolute/path/to/rea-agents-6.8.0.tgz \
  --apksigner /opt/android-sdk/build-tools/35.0.1/apksigner \
  --bc-provider /usr/share/java/bcprov.jar \
  --scratch /absolute/test-verifier-directory \
  --output docs/rea-native/validation/apk-signature-native.json
```

## Primary specifications

- [Android APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2)
- [Android APK Signature Scheme v3](https://source.android.com/docs/security/features/apksigning/v3)
- [ring 0.17.14 RSA key support](https://docs.rs/ring/0.17.14/ring/signature/index.html#rsa_pkcs1_-details-rsa-pkcs1-15-signatures)
- [Android APK Signature Scheme v3.2](https://source.android.com/docs/security/features/apksigning/v3-2)

These specifications justify the byte layout, digest construction, algorithm-list agreement, certificate/public-key binding and SDK-range consistency. Complete platform compatibility requires the explicitly unevaluated semantics above and a separately qualified producer/environment matrix.
