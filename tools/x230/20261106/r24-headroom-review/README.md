# Accepted R24: remaining optimization headroom

This is a preserved static review, not a new runtime implementation or a performance result. The accepted source baseline is `baab4def80be7af015b2e7a594cb302f66c4130e`. No Rust build, formatter, fixture, benchmark, x230/Mac API call, or runtime source modification was performed for the review.

## Read the final conclusion first

[Final report](final-02/README.md) and [machine summary](final-02/findings.json) distinguish measured R27 component evidence from rough planning assumptions. At the approximate 20,000 microseconds of controller CPU per call supplied by the parent task, a hypothetical 10 microsecond saving is 0.05%, and even 50 microseconds is 0.25%. The approximately 3.37 microsecond allocation-count extrapolation is an illustration, not a measurement, forecast, confidence interval or upper bound.

The recommendation is to record the two small allocation candidates without opening another complete qualification solely for them absent material absolute-cost evidence. The larger possible direction is a bounded persistent observation worker or an explicit batch primitive, after locating the actual stage costs. Neither is implemented here. Existing deadlines, authority checks, child custody, output bounds and acceptance gates remain requirements.

The original benchmark's CPU numerator is controller-only `utime + stime` for the same PID/start-ticks generation. It excludes local SSH child CPU and remote helper CPU. The existing 100 ms descendant sampler is incomplete diagnostic evidence and cannot be used to reconstruct those missing costs or subtract them from controller CPU.

## Unchanged report packages

| Published directory | Original local package name | Scope |
| --- | --- | --- |
| [static-01](static-01/README.md) | `r24-next-hotspots-review-01` | Exact R24 function locations, two small candidates, original historical patches/source and byte identities. |
| [final-02](final-02/README.md) | `r24-next-hotspots-review-02` | Absolute-cost scenarios, CPU accounting scope, persistent worker/batch constraints and related existing implementations. |

Every file within these two directories retains its original frozen bytes. Each original manifest remains in its package. Historical absolute paths and the prior-report paths in the original JSON are provenance, not rewritten Git paths; the table above is the publication mapping. Internal `history/`, `sources/`, `reference/`, and `baseline-fragments/` links retain their layouts.

[Accepted R24 source references](references/accepted-r24/) contain the full original pool, SSH, jobs and configuration files plus the accepted 220-input map, all verified against their original identities. [Prior historical overlap evidence](references/history-overlap/historical-overlap-review-01.json) and its seven original files preserve the earlier R25/R26/R28 and related inspection inputs. R29/R30 and R27 report/source originals are already inside `static-01`; the R27 component-method original is inside `final-02`.

R27 verified a small component improvement and was not promoted to complete runtime qualification or six-host acceptance. R30's original observation had one failed request and was not adopted; its deadline does not establish whether router or environment caused the failure. These scopes are preserved, and no failed sample is replaced by another attempt.

The accompanying Git blob catalog maps every published path to its exact blob ID, byte count and SHA256. The publication operation created blobs only; tree, commit and ref changes remain with the parent task. Static review does not establish a global performance optimum.
