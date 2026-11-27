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

## Remaining qualification

The common workflow still has its historical Hepta source pin and hosted cold
entry pending the final source freeze and pinned seven-root acquisition. This
commit only adds early catalog equality and the new admission controls there.
It is not a completed native workflow conversion.

A fresh native prebuild, unchanged-budget cold replay, source bootstrap,
formal release, complete original language fixtures against the admitted B3/M3,
and actual MCP integration must still run on the same final source. No current
whole-native, complete-language, common-integration, deployment, or old-stack
removal qualification is asserted by these component receipts.
