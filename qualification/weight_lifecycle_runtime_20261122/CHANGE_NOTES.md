# Retained qualification changes

## Before the first native checkpoint execution

The initial publication was retained in Draft PR #150 at
`546dae4a6f456bf51280b80fc498ff7079e26832`. Its first two CI attempts
stopped at locked dependency resolution, before compiling or executing this worker.
Neither attempt establishes a native lifecycle result.

Static composition review found that `Context::load` compared two distinct
protected hash domains as though they were the same. Source authentication hashes
all fields outside `network`. The semantic edit snapshot also protects the
frontend tensors `network.w1` and `network.b1`, excluding only the permitted
`network.w2` and `network.b2` readout. Consequently, a real request could not pass
the original check. This is a pre-execution composition defect, not a measured
model failure.

The correction verifies each domain separately against its original authority:

- Remove all of `network`, serialize with the existing Rust JSON convention, and
  compare with the authenticated source receipt's protected hash.
- Apply the existing full-native protected hash, retaining `w1` and `b1`, and
  compare with the semantic snapshot's protected hash.

The decoded source is still verified byte for byte against its original source
pin. No protected field, edit coordinate, dtype, radius, contract, or old hash has
been reclassified or weakened. The first actual successful checkpoint execution
must cross both checks before it can create a private execution root; its exact
binary and source identity will be retained by the campaign.

The standalone lock is updated from a resolver diagnostic which preserved all
compatible existing versions. The only version change is `libc 0.2.189` to
`0.2.191`, already required exactly by the recovery qualification dependency.
Unused root development dependencies `serial_test` and `tempfile`, and their
unreachable packages, are omitted from this standalone graph. The repository root
manifest and lock remain unchanged. The much broader first lockfile proposal was
not adopted.

These corrections still require exact-source CI and real checkpoint execution.

## First actual checkpoint attempt: provenance and local paths

Exact source `3c167ba81720a548bd994b5d25daaabc39c67143` passed both CI feature
modes. The first real fit11 invocation then failed closed before creating its
execution root: the adapter had incorrectly used the local gzip path as the
compressed checkpoint's logical source identity. The source authenticator
correctly required its original repository URL in the pinned transfer receipt.
This attempt used 0.11339 worker CPU seconds, performed no policy DP and made no
artifact-owner call. Its original stderr, result and outer process measurement
were retained; the second feature mode was not started.

The correction verifies the profile and its transfer-receipt pin, then requires
exactly one receipt row matching the actual compressed file SHA256 and complete
byte length. It obtains the original source identity from that authenticated row.
No match, duplicate rows or identical bytes recorded under multiple origins are
rejected. The existing source authenticator still checks URL, hash, length, the retained Git
blob field, gzip derivation and decoded source bytes. Local path relocation
only changes the file capability; it cannot create or replace provenance.

A focused regression covers relocated local paths, receipt tampering, ambiguous
same-byte origins and missing origins. Request schema, original input pins,
contracts, program, source bytes, legal edit domain and dependency lock remain
unchanged. New exact-source CI and a newly identified real campaign are required.
