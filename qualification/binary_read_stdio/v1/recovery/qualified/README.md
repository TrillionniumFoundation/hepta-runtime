# Actual HIA binary read stdio qualification

The frozen domain runs the exact original target helper, the production HIA ELF and
the observed HIA ELF on 48 shared immutable filesystem fixtures. It preserves every
stdin/stdout/stderr byte, each bounded child process and every native body/codec/stat
buffer, OS request/acknowledgement and formatter input/workspace/output buffer. The
production ELF cannot enable observation through input. Both native variants must
publish identical complete streams and exit codes. Success is compared as the full
JSON Value, since the original Python helper emits different JSON whitespace. Failure
requires byte-for-byte original stderr text, newline and exit code.

The domain includes partial input/output transport, EOF ownership, base64/hash and
read limits, high u64 offset/limit, expected-version refusal, non-traversing root/path
semantics, directory/FIFO/symlink/NUL refusal, descriptor-relative paths over 4096,
and ASCII/control/noncharacter filenames that force formatter output growth and
stdin growth. Eleven separate private-wire refusals include exact 128 MiB and
128 MiB plus one byte. They are distinct from the original user-facing input API.

All 155 helper processes run only after the complete source/domain/reader package
is frozen and fully read back from Git. The previously successful build is restored
from its complete uploaded archive, all objects/files/directories/modes are verified,
and its complete source, compiler, link and pack evidence is admitted without
recompiling or invoking any application. The producer runs are never replayed by
readers, physical mutants, relocations or uploaded-archive recovery.

Eight physically altered complete captures must be rejected; five honestly reseal
their changed compressed streams and nested process receipts. Two complete copies
must pass at different paths. Every pure admission rejects execution and evidence
writes and verifies all before/after bytes and metadata. All results, including
failure, retain a complete content-addressed archive before any eligible copy cleanup.

This is a private fixed read-mode helper closure. Configured host/root authority,
SSH direct and observation-pool process custody, cancellation and public SDK/audit
routing remain separate obligations. It does not install a public handler, replace
the whole runtime, or remove the legacy stack.
