# CI fixture and dependency repair

The original PR 71 run [40281007190](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/40281007190) and PR 72 run [40274087439](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/40274087439) completed with failing Rust tests. Format, check and Clippy passed; later Python gates and the release build were skipped. These failures remain part of the experiment history.

Two observed failures were `private request audit directory refused` in ordinary audit fixtures and `rg` not found in search fixtures. A poisoned global store lock then caused many secondary failures. The original CI jobs did not record their umask, so their precise umask is not asserted here.

An independent X230 counterfactual ran the original, SHA-pinned A50 test ELF with an explicit `umask 022`. The single `startup_preparation_creates_no_request_and_keeps_existing_identity` test reproduced the private-directory failure and exited 101. Its unmodified output and ELF SHA are in `umask-counterfactual.original.json`.

This repair gives ordinary private test fixtures explicit mode 0700 and makes CI run the unchanged full Rust test command with `umask 022`. Production permission checks and negative permission tests are retained. The asynchronous server fixture uses Tokio's directory builder.

CI now explicitly installs `ripgrep` and `python3-jsonschema`. All existing Python gates use `/usr/bin/python3`, matching the system package installation; their order and arguments are unchanged. `jsonschema` is an existing unconditional import in `dc_compat.registry`, but the original failed runs never reached that gate, so an observed Python CI failure is not claimed.

The permission fixture bytes were also included in the separate A51 diagnostic build on X230, whose full Rust test stage passed under umask 022. That superset build is not represented as a qualification of this smaller CI-only commit. The new GitHub run validates the exact commit published here. No performance or recovery acceptance follows from the CI repair alone.
