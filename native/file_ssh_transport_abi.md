# Configured native file SSH components

This component connects installed file authority to an actual self-pinned remote
HIA executable. It does not yet activate the default public controller transport.
The original direct SSH owner, observation pool, cancellation, complete error
formatting, default installer, and the remaining public file operations require
their own integration gates.

## Source and authority

The version 3 gateway captures the actual installed configuration replies for
operations 9 (read root), 10 (host transport), and 12 (native file entry). The
native_jobs field grants no file capability. HRCFFL01 supplies the configured
entry path and SHA256; HRCFTR01 supplies the selected host and SSH target.
The gateway accepts complete typed info/read inputs and uses the existing
parameter and call-plan HIA images. It snapshots the original input before
issuing private calls and follows HGRWS002 growth without replaying effects.

The policy uses HFBTRQ03: an 80-byte header containing magic, operation, sequence,
pool mode, and the five explicit lengths for typed request, host, plan, file
binding, and read-root feedback; the final word is zero. Those payloads follow in
that order. None is a caller-supplied replacement for installed configuration.

HFBSHP03 is a private transport plan with a 128-byte header. It records status,
operation, sequence, pool mode, the original 30000 ms budget, independent 8 MiB
stdout/stderr limits, argument count, stdin length, payload extent, error field,
configuration generation, and reserved zeros. Arguments are length-prefixed raw
UTF-8. The fixed argument prefix is:

    /usr/bin/ssh -T -o BatchMode=yes -o ConnectTimeout=8
    -o StrictHostKeyChecking=yes -o ForwardAgent=no

The captured installed SSH target and one HIA-quoted remote command follow.
The command invokes only the configured hia-file-entry with its full SHA256
and selected read root. This explicit native profile fixes the local SSH
resource; it does not reinterpret a configured host alias as a local filesystem.
Pool mode preserves the original 64 KiB command-plus-stdin admission limit and
does not fall back to the direct path.

The native remote service requires initialization. HIA emits initialize request
0, notifications/initialized, then tools/call request 1. Each record has a real
newline terminator. The initial attempt omitted that protocol handshake and was
correctly rejected with "Session is not initialized"; its complete original
evidence is retained.

## Remote entry and mechanical boundary

The entry is a static x86-64 ET_EXEC container with an RX load segment and
non-executable stack. Its fixed assembly only captures the initial CLI, maps
private memory, forwards fixed syscalls selected by HIA, and performs the
source-declared relocations. HIA validates exactly:

    hia-file-entry --pin SHA256 --local-read-profile ROOT

HIA hashes the entire actually loaded image, admits the fixed HFBENF01 footer
and embedded child extent, writes the admitted child into a sealed memfd, checks
the seals, and executes it through execveat. The child is the existing exact
native-local read composition, with an empty environment. No Python, Rust,
libc, dynamic loader, or old helper policy runs in this remote entry.

The HFBENF01 footer is 64 bytes: magic, version 1, guard offset and length, child
offset and length, full image length, and zero. HFBEPK01 is the exact packer
input: 64-byte header followed by the independently compiled guard and native
child. The HIA packer emits the final ELF. The source-declared mechanical template
is 760 bytes including the ELF header; its assembly body is 584 bytes.

The admitted entry has 1,968,969 bytes and SHA256
704910b80385a0b1e4308890390484067463bedcfd13d774bd1c71dfeb0a58aa.
Wrong image pins return 65; extra CLI arguments return 64. Those are tested entry
guards, not the original public file-error text contract.

## Private response decoding

file_transport_result.hepta accepts HFBRSQ01, a 64-byte header:
magic, operation 1/2, nonzero sequence, opaque process return, host-label length,
stdout length, stderr length, zero; then label, stdout, stderr.
Each stream retains the original 8 MiB capture ceiling.

HFBRRS01 has a 64-byte header: magic, result type, operation, sequence,
label length, data length, stderr length, original opaque process return.
The payload is label, data, stderr. Type 0 is the decoded successful text;
type 1 is a native-domain error; type 2 preserves a nonzero process result with
uninterpreted stdout/stderr. The decoder does not cast this private frame to
HRCFGM01, alter a nonzero exit, or claim the original public error formatter.

For a zero process return it requires the exact initialized reply and one
request-1 text result, rejects additional/truncated records, and uses the
existing full UTF-8/JSON-string decoder. Capacity growth retains HGRWS002
semantics. Process-error bytes may be arbitrary binary and remain untouched.

## Actual qualification and limits

The fixed compiler is Hepta d3e2c90173cf733e42b299d0c4274df4b593a12f.
All three bootstrap images remain 673413 bytes with SHA256
bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0.
No source, function, block, operation, capture, or deadline limit was raised.

The current evidence records:
- Native remote entry construction and repaired handshake: full original info
  and binary-read dictionaries, including real xattrs, plus CLI/pin refusals.
- Actual installed op9/op10/op12 replies consumed by HIA parameter, plan,
  gateway, and transport policy, followed by two real SSH requests to the
  installed remote entry. Full original dictionaries and canonical JSON bytes
  match. Paths include Unicode, quotes, a backslash, and a newline.
- Response decoder: 60 controls and 127 actual native calls, including the two
  actual SSH responses, malformed framing/UTF-8/surrogates, growth, capacity,
  full u64 sequence, and uninterpreted nonzero process results.
- The earlier exact-domain gateway controls and original failed handshake are
  preserved rather than replaced by the successor result.

The actual SSH supervisor in this qualification is an explicitly recorded QA
process. Default native child ownership and full public error fidelity remain
open. In particular, the existing native-local component's errors are not
automatically equivalent to the original Python helper's typed exception text.
The original Rust public deadline begins before encoding and queueing and must
remain so when this private plan enters the default controller.

Complete original files, modes, raw buffers, failed/pass observations, compiler
inputs, and actual SSH streams are in
qualification/native-file-ssh-component-20261128. Portable CAS manifests map
each original path to full bytes and source mode. Linux fixture xattrs are
captured; the Mac archive explicitly records that its Python lacks an xattr API.
