# Historical mkdir tool-identity diagnostic

This standalone, read-only probe explains the tool identity refusal in Runtime
[#140](https://github.com/TrillionniumFoundation/hepta-runtime/pull/140) without
editing its source-bound reader or rerunning original recipes. Use a checkout
of `641014b77003558f71414d2c33cc6c5a3ced0757` as `--runtime`. The probe checks
the existing helper bytes and never executes the examined tools.

1. Download the [original state artifact 14657511172](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/44783148352/artifacts/14657511172)
   and independently verify its SHA-256 is
   `19bb7092d995d4067d91523738dbff16d647444cd0e79c6438d0951301c79195`.
2. Read only the ZIP member `data/shell-capture-mkdir-original/build/result.json`
   into a temporary file. Its raw SHA-256 is
   `608d1aba31c522a350436c157e63fd0d6d45b2845b89f9a886ce6a69326410f6`.
3. From the host being diagnosed, pass the absolute Rust 1.95.0 executable
   selected by that host's CI and preserve the observed runner-image identity.

```sh
python3 -B qualification/mkdir_tool_identity_diagnostic/v1/diagnose_mkdir_tool_identities.py \
  --runtime /path/to/exact-runtime-checkout \
  --receipt /path/to/original-result.json \
  --receipt-sha256 608d1aba31c522a350436c157e63fd0d6d45b2845b89f9a886ce6a69326410f6 \
  --rustc "$(rustup which --toolchain 1.95.0 rustc)"
```

Exit 0 means an exact four-entry match. Exit 1 reports known field mismatches
and any unavailable paths. Exit 2 rejects unreadable or invalid inputs. Match
is not qualification: the original strict reader additionally binds source,
sysroot, loader configuration, dependencies and execution receipts. A probe
on a new host cannot establish which fields differed on the old aggregate
runner when that runner's identities were not retained.

Run the isolated regression tests with `python3 -B -m unittest discover -s
qualification/mkdir_tool_identity_diagnostic/v1 -v`. They use local byte fixtures,
not CI receipts or Rust compilation.
