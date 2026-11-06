# Existing Python CI regressions — 2026-11-03

All **19 existing workflow commands passed**, with **392 tests**, zero failed commands and no retries. These are the descriptor-relative, control-plane and X230 evidence-regression commands from `.github/workflows/ci.yml`. The exact-head and prospective-merge workflow jobs contain the same Python command list; this record executes that list once on the identified local source snapshot. It is not a GitHub Actions or synthetic-merge qualification.

## Source and execution identity

- Base Git HEAD: `f9756508462ebc72e814a12f5dbba1b067edabe4` plus the recorded working-tree source files.
- Workflow SHA-256: `1d77983c895c6142a392be0d7d1454dcb715bfba8517294dd01fc6e83477d09a`.
- Runner SHA-256: `f257c63abcc94cc6ceaf9c04c2bf22833c14591f63c18c1966c96a1c66d01115`.
- Source-set SHA-256: `fe8a7b6a729e7cffcd1c077a19859b67a970dd76d2d91cc394b81950bf1741ec`; the before/after inventories are identical.
- Captured source files: 1032.
- Interpreter: `Python 3.12.3`, executable `/usr/bin/python3.12`.
- Interpreter SHA-256: `e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f`.
- Installed jsonschema version: `4.10.3`.
- Started: `2026-11-03T12:27:38.851956+00:00`; finished: `2026-11-03T12:29:52.405376+00:00`.

The source inventories include the tracked and untracked inputs under `src`, `tests`, `deploy`, `tools`, `scripts`, `.github`, `.cargo`, `examples` and `benches`, plus listed root build/configuration files. Documentation, qualification outputs and Python bytecode caches are excluded. Raw before/after manifests and every command's stdout/stderr hashes are retained; `ARTIFACTS.json` fingerprints the retained files.

The later bounded AAPT2 ZIP-alignment correction happened after this successful run. `post-run-scope.json` records source differences observed when this documentation was written. The original measurement receipt is unchanged and does not claim that later Rust changes were tested here.

## Isolation and synthetic identities

Conflict review found no Cargo invocation or use of an existing runtime executable in these commands. Their real child processes are Python fixture programs. Tests use temporary private files, mocked service/SSH actions, or ephemeral loopback HTTP endpoints. They do not operate an installed service or contact configured production hosts. No Rust build or shared target directory was used.

Each command received its own fresh TMPDIR outside the repository, an explicit `/usr/bin:/bin` PATH and disabled bytecode writes. HOME retained its inherited value. Unrelated credential, SSH and runtime-owner environment variables were not passed. Fixture authentication strings such as `fixture-only`, `private-fixture-token` and `fixture-private-token` are deliberately synthetic credentials for disposable local tests; they are not deployment secrets. Temporary runtime state and token files were not copied into this documentation directory.

## Recorded commands

| # | Exact workflow command | Tests | Seconds | Exit |
| --- | --- | ---: | ---: | ---: |
| 1 | `/usr/bin/python3 tests/file_capabilities.py` | 9 | 1.368 | 0 |
| 2 | `/usr/bin/python3 -B tests/runtime_registry_page_tests.py` | 29 | 59.423 | 0 |
| 3 | `/usr/bin/python3 -B tests/test_native_canary_resume.py` | 10 | 5.580 | 0 |
| 4 | `/usr/bin/python3 -B tests/chatgpt_v11_layered_read_tests.py` | 23 | 0.566 | 0 |
| 5 | `/usr/bin/python3 -B tests/chatgpt_v11_process_start_concurrency_tests.py` | 15 | 0.466 | 0 |
| 6 | `/usr/bin/python3 -B tests/chatgpt_v11_v4_session_binding_tests.py` | 14 | 2.621 | 0 |
| 7 | `/usr/bin/python3 -B tests/runtime_workflow_owner_tests.py` | 15 | 0.366 | 0 |
| 8 | `/usr/bin/python3 -B tests/chatgpt_v10_single_v4_effect_tests.py` | 8 | 0.265 | 0 |
| 9 | `/usr/bin/python3 -B tests/chatgpt_v10_stream_custody_tests.py` | 18 | 0.366 | 0 |
| 10 | `/usr/bin/python3 -B tests/test_computer_http.py` | 19 | 1.819 | 0 |
| 11 | `/usr/bin/python3 -B tests/full_operator_facade_tests.py` | 31 | 10.743 | 0 |
| 12 | `/usr/bin/python3 -B tests/full_operator_cancel_tests.py` | 26 | 17.011 | 0 |
| 13 | `/usr/bin/python3 -B tests/chatgpt_request_identity_tests.py` | 21 | 7.936 | 0 |
| 14 | `/usr/bin/python3 -B tests/full_operator_session_recovery_tests.py` | 17 | 9.138 | 0 |
| 15 | `/usr/bin/python3 -B deploy/maintenance_20261017/native_rollout_tests.py` | 15 | 2.070 | 0 |
| 16 | `/usr/bin/python3 -B deploy/maintenance_20261017/recover_control_channel_tests.py` | 24 | 0.266 | 0 |
| 17 | `/usr/bin/python3 -B -m unittest discover -s tools/x230/20261028 -p '*_tests.py' -v` | 57 | 7.085 | 0 |
| 18 | `/usr/bin/python3 -B -m unittest discover -s tools/x230/20261029 -p '*_tests.py' -v` | 6 | 0.165 | 0 |
| 19 | `/usr/bin/python3 -B -m unittest discover -s tools/x230/20261030 -p '*_tests.py' -v` | 35 | 4.478 | 0 |

The descriptor-relative command ran 9 tests, the 15 control-plane commands ran 285, and the three X230 discovery commands ran 57, 6 and 35. `summary.json` retains each exact argv, working directory, temporary-directory identity, elapsed time, exit status, one-attempt count, unittest summary and both log digests. No failing attempt was replaced by a successful retry.

## Retained files

- `run_python_ci.py`: the executed command driver, which refuses an existing receipt or a changed workflow command list.
- `source-before.json` / `source-after.json`: measured source inventories.
- `summary.json`: actual execution results and interpreter/workflow identities.
- Numbered `*.stdout.log` / `*.stderr.log`: complete command logs.
- `post-run-scope.json`: explicit boundary for later source changes.
- `ARTIFACTS.json`: sizes and hashes of the retained files, excluding itself.
