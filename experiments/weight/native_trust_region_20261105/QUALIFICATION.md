# Qualification result, 2026-11-05

The frozen trust-region increment passed all six local engineering gates and
the complete preregistered actual-MCP replay on its first attempt. The result
qualifies the bounded solver, exact per-patch norm enforcement, byte
authentication, and normal-return restoration on these cases. It does not
establish new held-out task value or production eligibility.

## Source and executable identities

- Baseline public commit: `d85852b3c1708d9b2e8162badc07116999eff15e`.
- Baseline tree: `84f79718dda7ce1f976e6d21ad041031f4fd5c7f`.
- Rust toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`.
- Cargo lock SHA256: `15b9fb468eb34a210238657d132cbf19e961552d1313de488e1f14936bfa4e5f`.
- Executed binary SHA256: `6fc78b94860b579e3491158d9b434e22905432755a1efadb9f01d5136c24f6e4`.
- Local qualification receipt SHA256: `2dac7bd0b5c61489010aaf53295123452cbfcad3ae3fd66a205009b939208f5d`.
- Actual-MCP receipt SHA256: `03164419cbc1a8ea1b07bd59c879b4fc11136449cbf6e01c21d478eefa02667f`.

The exact ten-file source manifest is in `qualification/source_manifest.json`.
All ten source identities remained unchanged after the initial formatting step
and throughout both builds, tests, Clippy and binary compilation. The executed
binary was pinned and its bytes reverified after replay.

## Local gates and cost

| Gate | Result | Wall seconds |
| --- | --- | ---: |
| Initial format | Pass | 2.825 |
| All-features focused weight tests | 52 passed, 0 failed, 1 ignored | 869.036 |
| Clippy, all features and targets, warnings denied | Pass | 112.230 |
| No-default-features focused weight tests | 52 passed, 0 failed, 1 ignored | 633.923 |
| Build actual all-features CLI binary | Pass | 340.144 |
| Final format check | Pass | 2.876 |

The complete local phase took **1,961.079 wall seconds** and **3,678.963 child
CPU seconds** with two Cargo jobs. These costs include compilation; they are
not excluded from the delivered evidence. No failing or replacement attempt
occurred in this phase. The historical actual-head test remains conditionally
ignored and is not counted as executed. The full repository suite was not run
by this focused local command set. Official CI, if subsequently run, must be
bound to the exact published commit and recorded separately.

## Actual MCP replay

All seven planner cases passed the frozen independent F64-reference tolerance,
all returned F32 proposals met the exact binary numeric budget, and all edit
bytes reconstructed the returned F32 coefficients exactly. The maximum
absolute F64-reference discrepancy was **3.305e-12**.

| Case | Absolute F64-reference error | Native planner milliseconds |
| --- | ---: | ---: |
| Scalar active ball | 0 | 0.127 |
| Scalar inactive ball | 0 | 0.087 |
| Radius-zero singleton | 0 | 0.110 |
| Decimal-radius inward lowering | 1.819e-14 | 0.177 |
| Two differently weighted heads, common multiplier | 3.305e-12 | 0.210 |
| Public head, radius 0.05 times anchor norm | 1.610e-14 | 42.884 |
| Public head, radius 0.5 times anchor norm | 4.493e-16 | 5.976 |

The 60 norm checks span 22 families. The exact budget refused 28 over-budget
cases before publication. The other 32 reached the deliberately zero-gain
guard evaluation and were rejected by the unchanged strict gain gate, with
full source-byte restoration verified. Python `Fraction` checked the binary
F32 squared differences and binary F64 radii without a floating-point
tolerance. Four negative controls were refused: forged old bytes, duplicate
addresses, a negative radius, and an anchor not exactly representable in F32.
Absent and explicit-null optional radius commitments matched the historical
canonical request; supplying a radius changed the commitment.

The actual-MCP driver took **25.201 wall seconds**, **4.520 driver CPU seconds**,
and **6.677 child CPU seconds**. It includes private executable pinning, stdio
initialization, all requests, artifact operations, exact Fraction checks, and
receipt writing. Native planner times in the table are internal operation
measurements. They are not a training-speed comparison and do not include
reference generation, original training, LLM usage, transfer or energy.

## Public Hepta head replay

The new source is an explicitly F32-derived fixture. Its SHA256 is
`039b8c7fbbd4941e1cfc4e5808f731df311bf0af6f663f9bce78539838733115`.
The original public fixture provenance and precision conversion are recorded
in `fixtures/derived_public_fixture.json` and explained in `README.md`.

| Joint radius | Supplied-row MSE before | Supplied-row MSE after | Primary gate |
| --- | ---: | ---: | --- |
| 0.061370868989061945 | 0.041691370788794466 | 0.03928929265722098 | Accept |
| 0.6137086898906194 | 0.041691370788794466 | 0.03559057364424667 | Accept |

Both cases preserve the frozen Belief row byte for byte. The smaller radius is
active with a common F64 multiplier of approximately 0.05193546. The larger
radius is inactive. An additional exact-preservation constraint deliberately
conflicts with each candidate; both conflicting requests are rejected and
restore every original byte. These are engineered negative cases, not natural
model failures.

The MSE is evaluated on the supplied original TRAIN rows after the declared
F32 input/target/anchor conversion. No independent policy episode, held-out
distribution, end-to-end trading outcome, or checkpoint production promotion
was evaluated here. The numerical solver's feasibility evidence must not be
reported as improved task value.

## Independent checks and preserved evidence

Run `python3 experiments/weight/native_trust_region_20261105/verify_evidence.py`
to check the committed source and receipt hashes, reference agreement,
reconstructed F32 patch bytes, and all exact Fraction norm decisions. It uses
the Python standard library. Fresh replay of the executable is documented in
`README.md` and remains a separate qualification operation.

`qualification/evidence_manifest.json` binds the published files and records
the original raw-receipt hash. Planner receipts are complete and unmodified.
Guard receipts redact only local execution paths. Norm receipts retain the
budget and outcome fields required for the independent exact check. Build
logs have only private checkout/target path substitutions, with both original
and published hashes recorded. Original raw execution receipts remain in the
isolated qualification workspace. No private Trader data is included.
