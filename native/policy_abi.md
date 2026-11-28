# Native typed runtime policy

`policy.hepta` owns the deterministic decisions from the original configuration module: execution validation, environment and protected-input checks, protected-value selection, remote path prefix checks, lexical absolute-path normalization, and `Path` component containment. It returns decisions and exact diagnostics. It performs no command execution, filesystem access, network access, canonicalization, configuration installation, or lock acquisition.

The host policy and lookup status in this ABI are **administrator-owned typed inputs**. They must come from the installed configuration owner. They must never be copied from tool-call parameters or treated as proof of caller authority. A result is a value used by that owner, not an execution capability or filesystem authorization token.

## Original source and boundary

The reference is [src/mcp/runtime/config.rs at a0dcdda1991ec536d5e2d252c006a778993fa566](https://github.com/TrillionniumFoundation/hepta-runtime/blob/a0dcdda1991ec536d5e2d252c006a778993fa566/src/mcp/runtime/config.rs).

| Identity | Value |
| --- | --- |
| Original Git blob | `e55d9f536c069b7612f7a7cf81e691fd2394439c` |
| Original SHA-256 | `228f83aa263920ef16e6fca93ce52292cae3cecae5be4b47788a7070fee97f35` |
| Native source SHA-256 | `57d64450b81a46b92687a3efec056e2491e4c4a4ffde57a0999124d6bb0736d0` |
| Native image SHA-256 | `9c98db6df5b235ec4026a6a860b51e6f33cb09140eb28443f5e0cb4bb317d155` |

Execution includes the original `check_execution` lookup outcomes and complete `validate_execution` behavior. Environment and protected-input checks retain their lookup failures. Remote checking retains the distinction between no configuration, an unregistered alias, and a selected host. Host-name/SSH-alias resolution is a caller boundary; the frame carries its typed result and selected configured name.

`RuntimeConfig::validate`, private regex validation, worker profiles, policy installation/digesting, controller locks, canonical path resolution, symlink and file-identity checks remain separate owners. This component does not replace them or increase the count of migrated production tools.

## Function ABI

The first function is `f0(readbuf, mutbuf, mutbuf) -> u32`. Input, output and workspace are borrowed pointer/length pairs under Linux x86-64 SysV. The standard filter supplies up to 8 MiB input, 8 MiB output and 32 MiB workspace.

The return value is the complete initialized output length. `0xffffffff` means malformed typed input; `0xfffffffe` means insufficient output or scratch workspace. Neither refusal changes the output buffer. A domain rejection is a successful framed result containing the exact original diagnostic and is distinct from either ABI refusal.

## Input frame

The header is 128 bytes. Every numeric field is unsigned 64-bit little-endian.

| Offset | Field | Meaning |
| --- | --- | --- |
| 0 | Magic | Eight bytes `HRTPLC01` |
| 8 | Operation | 1 through 8 |
| 16 | Lookup status | 0: configuration absent; 1: configuration present, host/alias absent; 2: configured host selected |
| 24 | Execution mode | 0: isolated; 1: operator |
| 32 | Host flags | Bit 0 allow_execute; bit 1 allow_pty; bit 2 allow_write; other bits zero |
| 40 | Request flags | Bit 0 PTY; bit 1 cwd present; bit 2 explicit remote user; bit 3 explicit remote port; bit 4 remote write; other bits zero |
| 48 | Argument count | Argument strings |
| 56 | Environment count | Key/value pairs |
| 64 | Cwd-prefix count | Allowed cwd prefixes |
| 72 | Read-prefix count | Allowed remote read prefixes |
| 80 | Write-prefix count | Allowed remote write prefixes |
| 88 | Protected-path count | Protected path strings |
| 96 | Protected-argument count | Protected argument substrings |
| 104 | Denied-executable count | Explicitly denied names/paths |
| 112 | Allowed-dangerous count | Explicitly allowed dangerous names/paths |
| 120 | Reserved | Must be zero |

Each payload record is a byte-length word followed by exactly those bytes. Records occur in this order:

1. Five fixed strings: configured host name, requested SSH alias, primary value, optional cwd storage, containment root.
2. Argument strings in original order.
3. Environment key/value pairs, each key immediately followed by its value.
4. The seven policy lists in header order, from cwd prefixes through allowed dangerous executables.

Environment keys must be strictly increasing by UTF-8 byte order, with no duplicates. This represents the original `BTreeMap<String, String>` and preserves first-error order. Malformed maps are not sorted silently.

Strings must be valid UTF-8. Operations 7 and 8 instead accept raw Unix path bytes in the primary-value record; operation 8 also accepts raw bytes in the containment-root record. NUL is representable, and the original operation decides whether to reject it. No trailing frame bytes are allowed. Unused fields are ignored after type/framing checks. The cwd-present flag controls the optional cwd independently of its stored string.

## Operations

| Operation | Original owner and inputs | Result |
| --- | --- | --- |
| 1 | `check_execution` / `validate_execution`: primary executable, arguments, optional cwd, PTY request and host policy | Unit or exact error |
| 2 | `check_environment`: sorted environment map and host policy | Unit or exact error |
| 3 | `protected_value`: primary value and ordered protected lists; requires lookup status 2 | Optional matching string |
| 4 | `check_protected_input`: primary value and ordered protected lists | Unit or exact error |
| 5 | `remote_path_allowed`: primary value and read-prefix list used as the function's prefix argument | Boolean |
| 6 | `check_remote_path`: alias, selected name, primary path, override/write flags and remote policy | Unit or exact error |
| 7 | `normalize_absolute`: primary raw Unix path | Normalized raw path or exact error |
| 8 | `path_under`: primary candidate and containment-root record | Boolean |

Operations 5, 7 and 8 ignore lookup status. Operation 3 receives a selected typed host. The others preserve original lookup outcomes. In particular, the original remote-file check returns unit when runtime configuration is absent. That inherited-mode result must not become an authorization grant in a new runtime service: its configuration/effect owner must still require and select installed policy.

## Output frame

Every successful invocation returns a 32-byte header followed by its payload.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HRTPLR01` |
| 8 | Result tag |
| 16 | Scalar value; only Boolean results use a nonzero value |
| 24 | Payload byte length |

| Tag | Meaning | Scalar and payload |
| --- | --- | --- |
| 0 | Unit success | Scalar 0, empty payload |
| 1 | Domain error | Scalar 0, exact UTF-8 diagnostic |
| 2 | Boolean | Scalar 0 or 1, empty payload |
| 3 | `Some(protected_value)` | Scalar 0, matching UTF-8 string |
| 4 | `None` | Scalar 0, empty payload |
| 5 | Normalized path | Scalar 0, raw Unix path bytes |

Diagnostics have no terminal newline. The return count is 32 plus payload length.

## Preserved decisions

Execution retains this order: selected host; PTY/process permission; empty or NUL executable; absolute/no-parent executable structure; protected executable; explicit/default denial; cwd structure; cwd allowlist; protected cwd; then each argument's NUL and protected-value checks. The original 50 dangerous executable basenames and 15 dangerous environment keys are retained. Explicit executable denial remains effective in either mode. Operator mode skips only the original isolated-mode default restriction. Basename is the exact substring after the last slash.

Protected matching searches the path list first and argument list second. Empty patterns do not match. Matching is a literal case-sensitive substring operation; the first matching configured string is returned and used in the error. Each native substring predicate uses KMP with a 32-bit prefix table and linear work in its two input lengths. The enclosing list still invokes one predicate per visited configured entry; total work also depends on list size.

Environment iteration uses original sorted-map order. For each entry, NUL in the value precedes isolated-mode denylist checking and protected-value checking. No new environment-key validator is introduced.

Remote/cwd prefixes retain the raw-string rule: exact equality, or the configured prefix with trailing slashes removed followed by one slash. This does not canonicalize paths. Remote checking retains alias/override, absolute-path, parent-segment, protected-prefix and read/write order. Protected remote paths use prefix boundaries; protected execution values use substring matching.

Unix lexical normalization processes root, current-directory, parent-directory and normal components without filesystem reads. It rejects nonabsolute paths and traversal above the root. `path_under` compares Rust `Path` component prefixes: repeated slashes and nonleading `.` components are normalized by component iteration, while `..` remains a component. It does not resolve symlinks or establish real filesystem containment. The original canonicalization/effect owner must still precede filesystem authorization use.

Rust Unicode White_Space membership is preserved for executable trimming. Unix path errors preserve `Path::display()` lossy UTF-8 replacement, including malformed continuation boundaries and incomplete sequences. Successful normalized paths preserve original non-UTF-8 component bytes.

## Workspace and composition

Workspace reserves 256 control bytes and 16 bytes per input record for offsets and lengths. A substring predicate temporarily needs four bytes per byte of its current needle and reuses this space for the next pattern. Normalization instead needs scratch equal to the original path length. Scratch exhaustion returns capacity refusal and cannot publish an affirmative result. An earlier policy rejection does not require unused substring scratch.

Payloads are counted before output is written. Lossy path display can grow one invalid byte to a three-byte replacement character; the complete output size is checked before publication.

`policy_provenance.json` records exact source/function hashes for the UTF-8 validator imported from `native/text_budget.hepta` function `f2` and the Rust whitespace predicate from `native/line_endpoint.hepta` function `f2`. The test checks each imported function for exact structure after only its function name changes. Both functions reside in the final image; there is no runtime source interpreter, helper process or semantic fallback.

## Verification

`tests/hia_native/test_policy.py` accepts `HIA_POLICY_MANIFEST`, `HIA_HEPTA_DIR`, and `HIA_POLICY_CORPUS_DIR`, with explicit path overrides. It verifies HIA imports, runs native inputs, and exports actual requests/output plus hashes. `tests/hia_native/oracle_policy.rs` reads hexadecimal requests on stdin and emits `OK ` plus hexadecimal result per line, with no arguments.

The Rust oracle retains unchanged policy function bodies, constants and host lookup methods. Its substituted boundary is a test-owned typed configuration fixture representing selected, absent and unknown-host outcomes. Configuration installation and OS effects are not invoked. The test verifies the pinned original source and exact copied bodies before exporting the corpus.

The final source passed **11,655 valid native cases**, **188 malformed frames**, output/scratch capacity controls, **8 HIA VM cases**, and **3 standalone ELF calls** with an unusable `PATH`. Coverage includes all default denylist names, operator/isolated combinations, first-error precedence, Unicode whitespace, 3,249 component-containment pairs, raw-byte path diagnostics and long overlapping patterns.

The unchanged Rust oracle was actually compiled with Rust 1.95.0 and `--edition=2021 -O -C overflow-checks=off`. All 11,655 outputs matched the native corpus byte-for-byte. The run succeeded with exit code 0, complete durable output, confirmed terminal publication, and unchanged source/corpus files. See `policy_original_rust_comparison.json`.

| Retained comparison artifact | SHA-256 |
| --- | --- |
| Rust oracle source | `3aba586eb3e9a5cf818749efe3a9b916080bb983be374db3316dc1b25c502cad` |
| Requests | `6d217d1c0a4bc24ac189e92de807ef2ecd196f69447ffac4e0076b0d2a7deef6` |
| Native and Rust outputs, 1,550,158 bytes | `7d7147a69f9f2e46543b412726393c54ef5a6fcde20111521f54f40d128bb588` |

These are component-parity results for this typed boundary. They do not qualify configuration installation, OS authorization, production routing, or removal of the original runtime.
