# Native Workdir caller

This fixed Linux x86-64 profile contains the actual HIA Workdir parameter
decoder, public method body, shared request context and SessionWorkdir state,
installed configuration, path parsing and policy, local canonicalization and
the complete configuration regex dependency graph. Its executable is
`b1d92d5e912ac0d2b5fb87983dd94e80192443b4af5dc5fc91e45271e866255d`
(4,630,005 bytes). All 21 member images and the separate prefix and packer are
compiled by the pinned HIA compiler. The fixed executable has no Rust, Python
or libc runtime dependency.

The profile qualifies the local public Workdir method. It remains a private
qualification transport: the SDK routing, request audit/results layer and
remote filesystem branches must be connected separately. It does not mark a
production handler ported or authorize removal of its original owner.

## Actual owner order

Typed `WorkdirParams` decoding runs before request context application. The
decoder first executes the full HIA serde Value owner and then applies the
original struct rules, including sequence errors, duplicate-key handling,
field order, Rust Debug diagnostics and numeric formatting.

The public method then applies the actual first-context rule, reads current
SessionWorkdir, and follows the original reset or set branch. Reset skips the
path preflight. An unconfigured session skips the configured path preflight;
an installed configuration checks each trimmed `|` root before the executor
resolves the trimmed whole path. This distinction preserves literal pipe
directory names. Successful local set performs raw canonicalization and the
shared `is_dir` operation before updating SessionWorkdir. State changes precede
the final JSON response, as in the original method. Reset retains the session
root and the already claimed context latch.

The raw canonicalization owner preserves Unix path bytes. It implements the
complete checked primary canonicalization path, cwd recovery and two-private-
descriptor cleanup. Its errno text and NUL error match the actual original
`std::fs::canonicalize` observations. Human-readable path display uses the
original lossy UTF-8 behavior; the SessionWorkdir state keeps raw bytes.

## Private caller ABI

All integers are little-endian unsigned 64-bit words. The ordinary caller is
`native/workdir_caller.hepta`; the fixed bridge does not implement its path,
parameter or policy decisions.

| Message | Header and payload |
| --- | --- |
| `HMWDCF01` | 56-byte trusted initialization: USER present, USER length, connection mode, legacy capabilities present, legacy length, reserved zero; followed by raw USER and legacy JSON |
| `HMWDCR01` | 40-byte ordinary request: parameter length, metadata present, metadata length, reserved zero; followed by raw parameter JSON and full metadata JSON |
| `HMWDCS01` | 32-byte response: tag, reserved zero, text length; followed by the complete UTF-8 method response or parameter error |
| `HMWDCA01` | 96-byte child call at workspace offset 256: sequence, child ID, reserved word, request span, reply span, acknowledgment, result and two reserved words |

Response tags are 0 for method success, 1 for a method error and 2 for the
typed parameter error that precedes method entry. Parameter JSON, full metadata
and legacy capabilities each have an independent 8 MiB accepted domain. The
whole caller workspace is 256 MiB. The input staging span is 64 MiB and the
reply staging span is 128 MiB. USER is trusted startup data, may contain
non-UTF-8 Unix bytes, and is not read from ordinary request fields.

The common internal results are `0xffffffff` for a malformed private contract,
`0xfffffffe` for a capacity refusal and `0xfffffff0` for a pending checked child
call. `0xffffffd0` explicitly refuses the still unqualified remote execution
branch and clears the current caller phase. It is not a public filesystem
result and must not be presented as a completed remote implementation.

| Child ID | HIA owner |
| --- | --- |
| 1 | WorkdirParams and its serde Value child |
| 2 | Shared full RequestContext application |
| 3 | Shared SessionWorkdir state |
| 4 | Installed configuration accessors |
| 5 | Original PathSource parsing and resolution |
| 6 | Configured local path policy |
| 7 | Raw local canonicalization |
| 8 | Shared canonical-path `is_dir` and statx capability cache |

The 11 continuation phases validate every action word and checked child
envelope. A rejected receipt leaves the existing session state and output
unchanged and can be corrected and resumed. The selected tests identify their
policy and OS fixtures explicitly; actual filesystem semantics are established
by the separate paired original execution.

## Executable boundary

The fixed program accepts `--session-root ROOT` and an optional preceding
`--runtime-config FILE`. Descriptor 4 supplies the one-time `HMWINIT1` snapshot
(connection mode, legacy presence, legacy length, then legacy bytes). It must
reach EOF and is closed before ordinary input begins. The bridge reads USER
and `AT_SECURE` from the actual startup environment and auxiliary vector.

Ordinary stdin and stdout use an eight-byte length prefix. A completed
qualification response is `HMWDOB01`, followed by the caller-result length,
observed latch and shared-state-result length, then the actual caller result
and actual HIA SessionWorkdir Get reply. The observation envelope exists only
to compare the complete response and state with the original. Its latch
observation never drives business behavior.

The base shared mapping is 3,489,730,624 bytes of virtual address space. Caller,
parameter and PathSource workspaces have separate mappings. Raw canonicalize
uses its guarded dynamic workspace and two private descriptor slots. The
regex bridge uses distinct metadata slots and fixed call edges; it has no
filesystem or descriptor capability.

Configuration installation executes the original compile-only regex operation.
The valid and invalid pattern tests exercise syntax, Unicode data, HIR, NFA
and the controller. The matcher is fixed, compiled and embedded, but these
installation tests do not execute a fabricated match operation. Its separate
regex qualification remains the evidence for actual matching behavior.

## Build and retained evidence

`scripts/hia_native_workdir_service_build.py` builds all 23 roles from HIA,
including the prefix and SHA-bound packer. Final build and verification need
no assembler. They retain and verify complete compiler inputs, bounded output
buffers, actual stdout/stderr, compiler identity, receipts and packer process
completion. Verification checks every embedded image and call displacement,
not only the final ELF digest. The `.S` inputs document the fixed kernel
boundary and its derivation; they are not an alternate semantic runtime.

`scripts/hia_native_workdir_qualification.py` admits already completed evidence.
It executes no semantic HIA or Rust owner. It joins raw native and original
request/response streams, parameter observations, session bytes and actual
process completion. `check_workdir_evidence.py` damages retained bytes or
completion records, requires rejection, restores both bytes and mode, and
re-admits the complete baseline after each control.

## Observed qualification

The fresh portable run used the fixed HIA compiler and a new Rust 1.95 build
with the original 100 locked dependencies. All 175 installed rmcp 3.4.1 source
files were checked against the locked crate. The complete original Workdir
module and public-method/schema/preflight slices remained unchanged.

| Domain | Actual observation |
| --- | --- |
| Typed parameters | 680 cases, 1,416 HIA entries, 700 actual Value calls and 18 refusal/recovery controls |
| Caller receipts and ordering | 193 controls, 1,995 caller entries, 408 parameter entries and 407 Value calls; policy/OS fixtures explicitly marked |
| Complete local public method | 74 native and 74 original processes, 1,537 requests on each side, byte-exact text and raw SessionWorkdir state |
| Installed regex and immutable configuration | 18 processes and 36 successful requests per side, plus 6 startup refusals per side, exact first-error order and retained configuration locks |
| Raw canonicalization prerequisite | 89,499 native and original requests per side; 112 paired kernel cases and 3,954 owner effects per side, retained as its separate prerequisite observation |
| Evidence integrity | 20 damaged-evidence refusals and 21 complete baseline/restoration admissions; no new semantic execution |

The public-method domain includes all 680 typed cases, both connection modes,
metadata-versus-legacy priority, configured/absent/denied path policy, raw Unix
paths, symlink errors, Unicode trimming, literal pipe paths, reset/latch/error
ordering and simultaneous maximum parameter/metadata/legacy domains. Remote
policy refusals are actual original preflight results; allowed remote IO is
not simulated.

These observations are bounded qualification of this profile, not a new cold
compiler qualification or a proof of every theoretical usize allocation.
Private Get execution, the complete remote branches, production SDK routing,
shared audit/result persistence and whole-runtime activation remain separate
completion requirements.
