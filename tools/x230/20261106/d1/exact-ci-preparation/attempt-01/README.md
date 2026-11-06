# D1 exact Rust CI — actual qualification sealed, CI not yet executed

This delivery binds the original successful D1 qualification to one first exact Rust CI invocation. It is preparation and transport evidence, not a CI result or a performance result.

## Actual prerequisite

The original qualification job is `1a1aff8769c-fc05-6d26`. Its complete original report, preparation, source map, isolated-test summary and audit, native terminal record and read record are bound. The observed test counts are 1,651 passed, 0 failed, 34 ignored, 1,685 selected and 0 retries. The compiler source map has 222 inputs.

The final foundation is the corrected `d1_prerequisites.py` (53,934 bytes, SHA-256 `11875566eefa5532495d4411974faa2232a4339d3fd4ee1acae230c7394daba7`). It validates the actual preparation's four-field patch identity, including the Git blob identity. The Q-only prerequisite is 4,134 bytes, SHA-256 `427096289824d1159887f3bc7533fe8d3e61be055bff918a18b8bab0480a28e5`; qualification is sealed and exact CI is not sealed.

## Package boundaries

- `preparation/` preserves the 26-file unsealed template, source derivation, original R35 reference tools and static review. Historical waiting inputs remain original evidence; they are not the actual launch input.
- `sealed/` contains the actual 11-file seal. The six CI tools retain the original runner, nextest 0.9.137 audit, canonical workflow, commands, environment, zero-retry policy and child cleanup. The separate foundation avoids making CI depend on its own future success.
- `transport/` contains a deterministic 35,344-byte archive, deployment manifest and create-only installer. It deploys exactly 12 regular files under the existing D1 root. It does not alter source, qualification, cache or any original result.
- `independent-review/` contains the peer's template/seal and installer reviews. These are static reviews, not executions.

The all-features qualification ELF is retained under `qualification-01/`. The ordinary feature-off supplement and diagnostic measurement are separate future work. This package does not claim either was performed.

## First installation and launch

Root: `/home/qian/hepta-runtime-phase-cost-20261106-d1`.

Use the reviewed installer once with an absolute, owned, single-link staged archive:

```text
/usr/bin/python3 -B <staging>/install_exact_ci.py --archive <staging>/deployment.tar.gz
```

Archive SHA-256: `9c278ca931af69a0ae40a31b1ca09c2ff61ce8d00d1712004e666a5dd019fef0`.

Installer SHA-256: `f8f96165c454209999670bea0ebda162d01619c51509cb5bdc0e69f71920e035`.

After the installation's original successful terminal and output receipts are reconciled, the single CI invocation is:

```text
/usr/bin/python3 -B -u /home/qian/hepta-runtime-phase-cost-20261106-d1/rust-ci-tools-01/launch_exact_rust_ci_01.py --launcher-sha256 b96f70ff3270e4685521289c9e3442d8d1e62fd1e5a5d6f30889def195a979b5
```

The working directory is the D1 root. The plan is `rust-ci-plan-01.json`; output is `rust-ci-01/`. Both must be absent before first invocation. The original native process protocol and timeout/custody remain the operator's launch responsibility.

The installer takes an exclusive initial claim and preserves partial output on failure. Neither installer nor launcher automatically retries, deletes an earlier result, or selects a later successful attempt. Future CI terminal/read/result records must be retained separately with their actual original identity; none is fabricated here.

## Local actions

Only text generation, AST parsing, byte/hash checks, pure local input sealing and deterministic archive construction were performed for this delivery. No Rust compiler, formatter, CI runner, target binder, host API or benchmark was executed by the package author.
