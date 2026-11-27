# Native common readback preparation — 2026-11-27

The implementation in commit `fee1ffd56f8423f5e444ce82f3fe1867db57aab4`
adds a separate native cold/source-bootstrap admission path, installs and
verifies the formal native release package, and reads its actual
`agent-identity-manifest.json` and `agent-identity.image.bin` outputs. That path
does not call the hosted helper builder or rewrite the native source contract.
The historical hosted admission path remains a separate domain.

The new language runner binds the actual B3 and M3 images, native observer,
seven retained generations, and all 60 cold phase archive/journal pairs. It
runs the existing positive, refusal, and trap fixtures against both native
compilers with the original assertions. Its independent language references
are produced before that language execution; this is explicitly distinct from
the native cold gate's separate before-B0 reference obligation. The runner
does not claim that 60 native phases subsume the old hosted language suite.

## Exact-source controls

[controls.json](controls.json) binds these actual commands to the clean source
commit above and tree `0c6982c4a244aabca4b1b98a88b09f11bd711fa2`. It records
Python 3.13.5, command arguments, elapsed time, exit code, test counts, and the
complete stdout/stderr hashes. The small original logs are retained here.

| Controls | Actual result | Original log |
| --- | --- | --- |
| Cold/source and native release admission | 36 passed | [stderr](source-admission.stderr.log) |
| Native language custody and original fixture assertions | 9 passed | [stderr](native-language-controls.stderr.log) |
| Runtime CI contract | 6 passed | [stderr](runtime-ci-contract.stderr.log) |

These controls exercise positive and rejection cases, including mismatched
source, compiler and tool bytes, duplicate JSON keys, malformed inventories,
symlinks, missing generations or phase evidence, failed package verification,
wrong output, wrong trap signal, and missing modified-compiler refusals. Mocked
native release subprocesses in these controls are not native execution proof.

The installed-tool reader follows the public native capture bound of 64 MiB
per packed executable. In Hepta's `generate_hia_cold_build_entry.py`,
`postverify` state 715 calls `start_capture` with 67,108,864 bytes;
`generate_hia_cold_source_bootstrap_entry.py` retains that capture path.
The source-builder packer separately bounds each of its policy, compiler and
packer flats to 1 MiB, then combines them with an ELF prefix. Those individual
flat limits do not impose a 1 MiB limit on the complete packed executable.
The reader was corrected from that initial inference before any fresh native
product was admitted. B3, retained flat generations, the 1,107-byte observer
and source/tool manifest bounds are unchanged. Only the related positive and
negative reader controls were rerun for this correction. The
[three-control receipt](packed-tool-capture-controls.json) binds their exact
clean source commit, original logs, and four precise Hepta source references.
All three passed, including a packed tool and installer larger than 1 MiB and
rejection of a sparse tool extent greater than the native 64 MiB capture bound.

## Actual native observer compatibility smoke

[native-observer-component.json](native-observer-component.json) retains the
actual six-case component result. A historical, hash-checked native
`hia-source-build` compiled the current `selfhost.hepta` source in an empty
PATH. The resulting compiler constructed the modified chain; M1 differed
from M2, and M2 equaled M3. The actual HIA-emitted native observer then executed
the first existing positive, refusal, and SIGILL trap fixture with each of the
original and modified compilers. All six passed. The report retains the
individual native execution receipts and observed output identities.

The source builder was
`494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af`;
the observer was
`830b80e8b1acf852cb7cb103abe453cfdd800b34d6f992e5396769cb6c7f8e30`.
This smoke confirms observer/fixture compatibility. Its compiler came from a
historical component, so it does not establish fresh cold qualification or
complete language coverage for the current source.

The [initial environment failure](native-observer-component-initial-failure.json)
is also retained. That attempt compiled the source but stopped before its
first observer call because that Python environment did not expose
`fcntl.F_ADD_SEALS`. The successful attempt used the existing system Python
3.13.5 and a separate fresh output directory; no seal requirement or native
execution control was removed.

## Complete original fixture component run

The subsequent [component summary](native-language-component-summary.json)
records a real execution of the entire current fixture inventory using the
same historical initial compiler and a complete, isolated export of Hepta
`f39c7a9cef00a1a0bf0c9ad585b54dd0a355e002`. Every exported file matched its
immutable Git blob before execution; all source bytes were checked again
afterward. Both component fixed-point chains were executed afresh with the
native observer. Each of the six produced compiler images was 641,344 bytes,
within the existing 1 MiB admission bound.

| Original witnesses | Per compiler | Both compilers |
| --- | ---: | ---: |
| Positive programs and expected output | 238 | 476 |
| Transactional refusals | 286 | 572 |
| Checked shifts, arithmetic, casts and word-memory traps | 238 | 476 |
| Total original cases | 762 | 1,524 |

All 1,524 cases passed. The two actual fixed-point checks and the source
unchanged check brought the component result to 1,527/1,527. All ten original
semantic aggregate assertions passed with no skipped tests. The independent
reference report retains all 1,183 scalar witnesses and the original negative
and trap oracles. It preceded this execution; it does not replace the native
cold gate's before-B0 reference obligation.

The complete original [execution report](native-language-component-full.json.gz)
and [independent reference report](native-language-component-reference.json.gz)
are retained with lossless gzip compression, together with original
[stdout](native-language-component.stdout.log) and
[stderr](native-language-component.stderr.log). The summary binds compressed
and original byte counts and SHA-256 digests. Each compiler's 11,619 raw
evidence files was independently verified and archived by the existing
`archive_completed_stage` implementation. The summary records both retained
ZIP identities; the roughly 10 MB archives are not duplicated in Git.

The run completed in 61.145 seconds. Its original native invocation limits
were unchanged. A 512 MiB storage reserve was checked before every native
invocation; the lowest observed free space was 2,953,695,232 bytes.

Two earlier attempts remain failures. The
[incomplete export report](native-language-component-incomplete-export.json)
stopped at the complete source inventory check before any new invocation. The
[disk exhaustion report](native-language-component-enospc.json.gz) and
[original traceback](native-language-component-enospc.stderr.log) retain the
later attempt's successful generations and 56 positive observations before
ENOSPC interrupted the next output write. The successful attempt used a
separate directory on the other filesystem with sufficient space; no failed
attempt was relabeled or used to fill missing results.

This is complete finite-fixture **component** compatibility, with an initial
compiler derived from the historical builder. The original eleventh assertion
requiring cold evidence was explicitly excluded from this component run and
remains required in the actual native-cold runner. This result does not admit
a fresh native cold report, qualify the final integrated source, or establish
common MCP integration.

## Pinned native bootstrap distribution

`tests/hia_native_bootstrap_distribution.py` reads
`native/bootstrap/linux-x86_64/manifest.json` from a separately pinned Hepta
distribution commit D. Its schema is
`hepta.hia.native-bootstrap-distribution.v1`. D must be a direct child of the
frozen source F, with every Git entry outside that added directory unchanged.
The manifest binds F's complete commit/tree identity, its native authority,
binary source and recipe inventories, both entry sources, eight executable
files and the original construction evidence. All declared bytes and Git
executable modes must match; missing, undeclared, substituted, symlinked or
hardlinked artifacts are refused.

The seven fixed initial roots retain their native 64 MiB capture bounds. The
current `hia-cold-build` entry retains its separate 1 MiB bound. The reader
copies those actual bytes to fresh mode-0500 files and copies exactly the
frozen authority/contract source closure to a separate mode-0400 source tree.
It compiles no source and constructs no seed. Its positive custody result does
not establish that those programs ran; the following native prebuild must
independently rebuild and compare the seven roots.

Nine new controls use synthetic Git F/D histories and explicitly non-executable
fixtures. They cover exact staging, source/manifest binding, missing and extra
assets, hidden byte drift, symlinks and hardlinks, unsafe paths, duplicate keys,
both original extent boundaries, changes outside the distribution, wrong
parentage and preservation of an existing report. All nine passed. The
[exact-source control receipt](bootstrap-distribution-controls.json) binds
commit `18f40971fdcdd7a365db1b471128664a01bd81ba`, the original stdout/stderr,
all fifteen workflow script digests and syntax outcomes, and the actual
missing-pin refusal. The existing REA source mapping check also passed at that
commit without another projection refresh; its 229 OPEN operations and zero
qualified operations are unchanged.

The common workflow now wires the actual native prebuild, sixty-phase cold,
post-cold admission, formal release, original language fixtures and real MCP
integration. Native construction uses an empty PATH. External language
references run without inherited HIA helper selectors. The release package's
native install and verify outputs supply the identity helper; the old hosted
cold/helper construction is not used by this workflow path.

Both F and D pins are deliberately empty until the real final source and its
verified distribution are published. A dedicated gate reports **HOLD** and
exits 1 before attempting either checkout; empty pins never select a default
branch. Local validation parsed the YAML, checked all fifteen shell blocks and
actually exercised that missing-pin refusal. No source or artifact identity
has been invented to make the framework runnable prematurely.

Cold keeps its original 180-second qualification and 3-second cleanup bounds.
Ordinary native release explicitly keeps its original 1,800-second selected
deadline. The 90-minute aggregate CI job allows the added native construction
stages, release, external fixtures and evidence retention; it does not change
any native cold budget.

## Remaining qualification

A fresh native prebuild, unchanged-budget cold replay, source bootstrap,
formal release, complete original language fixtures against the admitted B3/M3,
and actual MCP integration must still run on the same final source. No current
whole-native, complete-language, common-integration, deployment, or old-stack
removal qualification is asserted by these component receipts.
