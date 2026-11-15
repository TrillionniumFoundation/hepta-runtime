# X230 A48 archive experiment: qualified source, failed large gates

**Qualification passed; performance adoption failed.** A48 adds bounded two-reader
full-original validation to the fresh page cohort path. It passed all six Rust
qualification stages and the small-archive regression guard. The large archive
comparison completed every planned call but failed C4 correctness and two CPU
regression gates. These are independent facts, with all failed outcomes retained.

| Evidence | Result |
|---|---|
| [Design and qualification](qualification-design.md) | 1,266 passed / 0 failed / 23 ignored; fresh test/release artifacts |
| [Small fixed comparison](small-results.md) | 8,192 measured / 8,848 total correct; all six gates pass |
| [Large fixed comparison](large-results.md) | All 80 attempts; candidate C4 30/32; 13/16 gates pass |
| [Next investigation](next-steps.md) | CPU/context-switch regression; separate bounded diagnostic and conditional batching hypothesis |
| [Complete tested source map](source-tested-map.json) | 168 compiler-input files |
| [Qualified Git object map](qualified-git-object-map.json) | Actual X230 body hashes/Git blob IDs; four expected source changes |
| [Original evidence manifest](evidence-manifest.json) | Exact original UTF-8 report/log bodies and declared exclusions |

The complete A46 comparison is preserved in [its own report](../a42-a46-release-small.md).
A43 owner-barrier qualification/lifecycle results are in the independent
[PR #72](https://github.com/TrillionniumFoundation/hepta-runtime/pull/72).
The two source changes have not been combined and qualified together.

The new source, fixed tools and reports are published for review. The original
benchmark deadlines, numeric gates and complete failed inventories are unchanged.
No result here establishes saturated-server throughput, multi-host acceptance,
steady-state memory, power-loss durability, production deployment or theoretical
optimization exhaustion. See [current native authentication admission](../native-auth-20261026.md).
