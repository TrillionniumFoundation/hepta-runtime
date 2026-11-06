# R27 borrowed observation serializer experiment

**Disposition: component improvement verified; not promoted to full qualification
or six-host acceptance; not adopted.** The full gates were not run or evaluated.
The [complete report](../../../../docs/X230_OPTIMIZATION_20261105_R27.md) explains
the change, actual results, retained failure, scope and stopping decision.

The independent experiment branch contains the R24-based source change and seven
new sibling regression tests. The initial code/protocol checkpoint was
`9d01233e21ef57190b43661afa18674cf1e837e9`. Only the component was compiled and run;
the complete runtime's expected 1,652-pass/34-ignored qualification was not run.

## Results

| Ordinary case | CPU A to B, us/call | Allocation calls A to B |
|---|---:|---:|
| Python status | 0.859366 to 0.403238 | 12 to 2 |
| Python read | 1.242566 to 0.461635 | 14 to 2 |

One realloc remains in each ordinary case. The equal mix of ordinary Python
status/read fixtures saves 0.61852976 us and 830.5 cumulative requested allocation
bytes per preparation call. This is
about 0.003201% of the published historical R24 controller CPU/call, a magnitude
comparison rather than measured whole-runtime throughput or RSS. All six cases,
all 48 timing samples and all 12 allocation records are preserved below.

## Original successful attempt 02

- [Native request and start](evidence/component-02/native-start.json)
- [Strong native terminal and complete native logs](evidence/component-02/native-terminal.json)
- [Full component report](evidence/component-02/report.json)
- [Every timing sample and summary](evidence/component-02/timing.stdout)
- [Every allocation record](evidence/component-02/allocation.stdout)
- [Exact compiler identification](evidence/component-02/compiler-version.stdout)
- [Actual dependency product fingerprint](evidence/component-02/qualified-product-fingerprint.json)
- [All retrieved file identities](evidence/component-02/receipt-verification.json)
- [Full readback response](evidence/component-02/readback.json)

All five stage stdout/stderr files are retained in that directory, including
empty files. ELF and dependency archive bodies are omitted explicitly; their
native hashes and exact paths remain in the report.

## Preserved original failure and correction

Attempt 01 stopped before any Rust compiler or sample because the old R25 cache
fingerprint was absent. It was not a failed performance run or discarded sample.

- [Original failed report](evidence/component-01/report.json) and [exception](evidence/component-01/exception.txt)
- [Original request/start](evidence/component-01/native-start.json) and [terminal/log](evidence/component-01/native-terminal.json)
- [Readback](evidence/component-01/readback.json)
- [Read-only dependency inventory request/start](evidence/dependency-layout-native-start.json) and [result](evidence/dependency-layout-native-result.json)

The correction selects the four direct dependencies matching the pinned R26
product fingerprint in the current cache. No Hepta runtime library is linked, and no cause of the
old cache absence is asserted. Benchmark source, cases, rounds and counts remain
unchanged.

## Source, methods and audits

- [Exact candidate patch](borrowed-observation-serialization.patch)
- [Unchanged source-extracted benchmark](component/bench.rs) and [generator](component/generate.py)
- [Successful attempt02 runner](component/run_component_02.py) and [exact request](component/attempt02-native-request.json)
- [Original attempt01 runner](component/run_component.py) and [original request](component/planned-native-request.json)
- [Component method and scope](component/README.md)
- [Root arithmetic review](reviews/root-arithmetic-review.json)
- [Independent full audit](reviews/independent-review-01.md) and [structured audit](reviews/independent-review-01.json)
- [Prequalification source map](reviews/prequalification-source-map.json)
- [Unchanged full acceptance gates](PREREGISTRATION.md) and [machine-readable plan](preregistration.json)

The original independent review retains local scratch paths and sandbox links as
provenance. Use the repository evidence links above for GitHub navigation.

The prepared full qualification/campaign materials are archived under
[prepared-not-executed](prepared-not-executed/README.md). They are retained planning
work, not executed tests or ready-to-launch approval. The observed old cache
absence requires updating and rechecking their cache bindings before use.

Further serializer-capacity tuning stops on the current absolute-cost evidence.
Any future integration still requires full Rust qualification and the frozen
six-host acceptance; this experiment does not establish a global optimum.
