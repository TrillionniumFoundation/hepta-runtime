# Native regex dependency and configuration continuation

These components execute HIA compiled by the pinned native compiler. They do not call Rust, Python, libc, an external regex service, or a dynamically selected plugin. The original reference crates are test dependencies only: regex 1.13.1, regex-syntax 0.8.11, regex-automata 0.4.18, aho-corasick 1.1.5 and memchr 2.8.3, with the exact original Cargo checksums.

The installed configuration route is real: administrator startup invokes `config_owner`, which invokes the validator twice in the original load/init order; the validator calls the native regex controller for each `extra_arg_patterns` element. Its first failing pattern produces the original validation error before state-directory preparation. The standalone configuration MCP service advertises `host_list`, `effective_config` and `execution_shadow_admit`; the separate combined runtime MCP profile also connects `view`. This dependency does not implement or advertise `privileged_run`, and does not authorize a command merely because a pattern matched.

## Fixed call graph

| Owner | Local selector | Configuration image | Combined runtime image | Allowed child selectors |
|---|---:|---:|---:|---|
| Configuration validation | 3 | 3 | 3 | 15 |
| Syntax/AST | 10 | 11 | 31 | 11 |
| Immutable Unicode data | 11 | 12 | 32 | None |
| HIR translation | 12 | 13 | 33 | 11 |
| Forward/reverse Thompson NFA | 13 | 14 | 34 | None |
| Boolean NFA matching | 14 | 15 | 35 | 11 |
| Regex controller | 15 | 16 | 36 | 10, 12, 13, 14 |

Local selectors remain unchanged when the fixed subtree is placed in either composition. The 17-image configuration and 37-image combined runtime keep result publication at physical image 10; their builders bind each regex selector to the exact physical image shown above. Within configuration/regex validation, only the existing configuration filesystem image 1 may yield an OS effect. The regex subtree is pure byte-memory computation. Its module IDs, call offsets, images, source hashes and private workspaces are fixed by the build profile. Neither tool arguments nor configuration text can select another executable, module or child span.

Every component uses `f0(readbuf, mutbuf, mutbuf) -> u32`. Ordinary return values are exact output byte counts. `0xffffffff` rejects malformed internal input or receipts; `0xfffffffe` indicates insufficient buffers; `0xffffffe0` yields a fixed child continuation. Parser/translation/NFA domain refusals use their documented `0xfffffffd` code, and the parser separately distinguishes private arena exhaustion. A refusal never publishes a partial output. Input, output, private scratch, state and continuation footer spans are checked independently.

## Public dependency record

All integers are little-endian u64. The controller input is exactly:

| Offset | Value |
|---:|---|
| 0 | Eight bytes `HRGEX001` |
| 8 | Operation: 1 validate, 2 Boolean match |
| 16 | UTF-8 pattern byte length |
| 24 | UTF-8 haystack byte length; zero for operation 1 |
| 32 | Pattern, then haystack bytes |

The controller applies the exact original wrapper `\A(?:PATTERN)\z`. It does not escape the administrator pattern or replace it with an apparently similar anchoring operation. In particular, patterns that close and reopen the wrapper group retain their original meaning. A one-pattern cache compares the complete pattern bytes and is published only after both forward and reverse compilation succeed.

Its 32-byte result is `HRGREX01`, followed by status, capture count and Boolean matched value. Status 0 means valid; 1 is original syntax/translation rejection; 2 is the original 10 MiB NFA allocation limit; 3 is a private component capacity refusal. The configuration validator converts syntax/size failures to its original argument-regex error and keeps private capacity failures separate. The controller does not expose original parser prose through this internal ABI; the complete original prose remains in comparison artifacts.

## Component records

| Owner | Input | Successful output |
|---|---|---|
| Unicode data | Eight bytes `HRGDAT01` | Immutable indexed Unicode data bytes |
| Unicode query | `HRGUNI01`, operation, two byte lengths, two fields | Exact requested class/fold/predicate projection |
| Syntax | `HRGAST01`, mode (1 wrapped, 2 raw), UTF-8 length, pattern | `HRGTRE01` header, 64-byte preorder nodes and byte pool |
| HIR | Complete validated `HRGTRE01` | `HRGHIR01` header, 96-byte preorder nodes and byte pool |
| NFA | `HRGNFI01`, reverse flag, allocation limit, graph flag, HIR | `HRGNFA01`, exact allocation accounting and optional graph |
| Matcher | `HRGMAT01`, graph byte length, haystack byte length, graph, UTF-8 | Eight-byte Boolean value |

The syntax and HIR records preserve source positions, explicit flags, capture identities, Unicode/byte-class distinctions, concatenation and alternative order. Translation retains the original simplification and case-fold behavior. The NFA owner preserves builder allocation order, literal-trie behavior, UTF-8 range structure, capture slots, sparse/union edge charges and reverse compilation. The matcher evaluates the original look assertions, including CRLF and Unicode word-boundary variants. These are not translated to a host regex dialect.

Regex Unicode classes are pinned to the original crate tables. Capture-name alphabetic/alphanumeric predicates are separately pinned to the actual Rust 1.95 standard-library Unicode domain. The original recipe therefore explicitly verifies Rust 1.95; changing the host's default Rust toolchain does not silently change these tables.

## Resource and scope limits

The native build uses existing `standard`, `history.v1` and `serde-json.v1` buffer profiles. The regex controller and syntax/HIR/NFA owners have private 256 MiB workspaces in composition; the Boolean matcher has 32 MiB and the immutable data leaf has 64 KiB. Internal byte-buffer transport bounds and administrator configuration-file bounds remain explicit. The syntax full-pattern test includes 64 MiB of valid source, but that one case does not prove every expression of that length fits its AST/HIR arena.

**Unconstrained regex resources are not closed.** Very large valid AST/HIR representations may exceed private arenas or intermediate output spans before reaching the original NFA allocation decision. Full equivalence of every optional original meta-engine optimization and allocation path is not established by the finite corpus. These boundaries are capacity failures, never acceptance by a fallback implementation, and they prevent claiming complete original RuntimeConfig/runtime parity or removing an original handler owner.

## Verification contract

The native suites retain all 6,560 Unicode cases, 18,976 AST cases, 34,130 HIR cases, 3,584 forward/reverse NFA budget cases, 65,440 Boolean matches and 3,694 configuration-regex cases. The NFA corpus is divided into two fixed, disjoint process shards; their ordered union and all 576 exact-limit/one-less controls are required. Sharding changes no case or per-process deadline. The native tests also cover malformed records, output atomicity, corrupted child receipts, persistent recovery, actual static ELF framing and the administrator installation chain.

`hia_native_config_qualification.py` admits actual build and suite receipts, not reconstructed success messages. `hia_native_regex_qualification.py` requires complete retained ELF output, full native corpus bytes and both NFA shards. Original comparison uses one shared Cargo build per locked reference project, then executes every complete domain. No observed prior Rust build is called a fresh execution. Historical SIGKILL and harness-path failures remain separate failed observations and are not converted into successful qualification.
