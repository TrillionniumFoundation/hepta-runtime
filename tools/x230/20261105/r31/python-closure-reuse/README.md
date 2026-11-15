# R31: reuse of historical Python regression evidence

This package verifies that the **85 dependency inputs used by the successful R29 Python CI run are identical to the inputs published at R31 commit `c039688312ceb09b3d26d1cdd50f9118eb11129f`**. It also compares those inputs with the complete local frozen R31 source directory. This is a same-input historical regression proof; no Python gate is rerun.

## Result and scope

The local verification completed successfully. Its complete machine-readable result is [proof.json](proof.json); the reproducer is [verifier.py](verifier.py).

| Check | Result |
| --- | --- |
| Original dependency inputs | 85 files; 1,862,543 bytes |
| Archived input vs. fixed published Git blob vs. local frozen file | All 85 byte-for-byte equal; size and SHA256 verified |
| Git blob identity and mode | All 85 match the original manifest and published tree; local executable bits match Git modes |
| `20261028`, `20261029`, `20261030` discovery sets | All three sets match exactly, including the complete set of matching filenames |
| R31 source changes relative to accepted R24 | Exactly `jobs.rs`, `jobs_cancel_wait_fixture.py`, and `jobs_cancel_wait_tests.rs` under `src/mcp/runtime/` |
| R31 changed source paths intersecting the Python input closure | None |
| Original Python commands | All 18 passed; return code 0; no retries, timeouts, or cancellation |
| Original per-gate streams | All 36 verified against their recorded sizes and SHA256; 44,938 bytes total |
| Original runner streams | Both verified against the outer receipt |
| Original native streams | Full stdout 8,077 bytes and stderr 0 bytes; raw read response, EOF/offsets, saved bytes, terminal counters, and outer JSON agree |

The source-change comparison covers the compiler source/configuration paths, not the entire repository: publication adds documentation and evidence. The only Python-closure path also present in the R31 compiler input map is the unchanged `src/mcp/runtime/fileio.py`. The new pidfd fixture is outside this historical Python closure and receives no coverage claim from this proof.

The original archive normalizes its member permissions. Those container permissions are **not** reused as Git modes. Mode equality comes from the original manifest's `git_mode`, the fixed published Git tree, and the executable bit of each local frozen file.

## Original execution and immutable references

The original x230 native job was `1a1ad72111c-fc05-59eb`. Its terminal state was `succeeded`, exit code 0, with complete, durable, untruncated output and terminal publication confirmed. The inner run started at `2026-11-05T20:41:38.504313+00:00` and finished at `2026-11-05T20:43:31.845561+00:00`.

The original command runner used the byte-bound subset at `/home/qian/hepta-runtime-optimization-20261105-r25/ci-gates/ci-inputs`, under Python 3.12.3. Although it retained the historical `hepta-r25-external-python-ci-results/v1` schema and manifest reference commit `1aa98d3c94d0253999a491c967ccc94b314e87c8`, this was an actual R29 execution, not a reused R25 result. Its outer receipt explicitly records that distinction.

The reproducer reads these existing files from **fixed commit `c039688312ceb09b3d26d1cdd50f9118eb11129f`**, never from moving `HEAD`:

| Git path below `tools/x230/20261105/r29/` | Bytes | SHA256 |
| --- | ---: | --- |
| `evidence/qualification-ci-01.tar.xz` | 1,942,216 | `bfe5852ce915f8430862d6ac456bf366cac4df33b03c542cfb80290d49a895b3` |
| `evidence/native-operations-custody-01.tar.xz` | 7,443,600 | `8fe9b50926f919a6e1a74f8df1b6ed80c0f4080ff6ed1a178cafb1f25ba1c05c` |
| `receipts/python-report.json` | 16,692 | `64c89946e08ab74420efab2c0dc4a17b76b4e836d4e2f76d87c4ee212b1798fa` |
| `receipts/python-outer.json` | 9,579 | `68195d90ad8b6a6f18f17c24075d9db9ca73a8dc70d99a3aa3a70ba6e12420fb` |
| `receipts/python-native.json` | 731 | `f81b9cc08f4a81cb79f1320c9813c101d7987cbd70e2238a88b3c42121905718` |

The qualification archive contains `published-python-inputs/ci-gate-manifest.json` (45,857 bytes; SHA256 `bf0df5f7d19ebd149854fbf75887fb0fb136f18a63a0c240abf8420655fb195e`). Its `workflow_git_blob` field is the **string** `34afc29edffd3130df158601c6a14fee5efbf79c`, not an object. Its `workflow_path` is `.github/workflows/ci.yml`. Each element of the `input_files` list separately has `path`, `bytes`, `sha256`, `git_blob`, and `git_mode` fields.

`proof.json` records the exact archive member paths, their hashes, every original command and stream identity, and all 85 common input identities. The native companion is read only for the original Python operation; this verifier does not re-audit unrelated Rust, performance, or custody results.

## Known difference in the private x230 source directory

The canonical workflow included in the 85-file closure is 7,631 bytes, SHA256 `b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51`, at both the fixed published commit and the complete local frozen source.

The previously captured private x230 `SOURCE/.github/workflows/ci.yml` is **different**: 7,235 bytes, SHA256 `5574840f604a3c7963a274592ac2468a43fdd04cdaa7122851c271188a11065d`. Its unmodified local copy is included as [private-source-workflow-original.yml](private-source-workflow-original.yml). The verifier binds that copy by size and SHA256 and records its exact diff. Each of its two jobs contains only the `20261028` discovery command; the canonical workflow additionally has `20261029` and `20261030` discovery commands in each job. The YAML scalar also changes to a multiline block for those three commands.

Consequently, **85/85 equality applies to the published R31 commit and the complete local frozen source, not the entire private x230 `SOURCE` directory**. The verifier does not contact x230 or claim to reauthenticate the remote origin of the previously captured copy. The original 18-command R29 execution used the separate canonical input subset described above.

## Reproduce locally

Only the Python standard library and local Git are needed. All fixed Git objects must already be available: lazy fetch, prompts, and optional Git locks are disabled. A sparse worktree is sufficient for `--repo`, because published inputs are read from Git objects. `--source` must identify a complete local frozen source tree containing all 85 inputs.

The exact command used for this proof was:

```sh
python3 -B /workspace/scratch/84d692c73f59/r31_python_closure_reuse/verifier.py \
  --repo /workspace/scratch/84d692c73f59/hepta-runtime-r31 \
  --source /workspace/scratch/84d692c73f59/review_optimization/r31_candidate/source
```

The verifier prints the JSON proof only after all checks pass and exits with status 0. On a failed check it exits nonzero with a diagnostic on stderr. It writes no files. Archives are SHA256-pinned before opening, read entirely through in-memory tar readers, and never extracted. Archived scripts, tests, and auditors are neither imported nor executed. The optional `--private-workflow-copy` argument defaults to the included original copy beside the verifier.

The saved proof is deterministic for the same verifier and input paths. Its `local_frozen_source` field records the local directory used, so reproducing from another directory changes that field without changing the content-comparison results.

## Limits

This proof establishes continuity of the inherited 85-file dependency manifest and its successful historical regression results. It does not repeat discovery of every possible dynamic or external dependency.

It is not a new R31 Python execution, a hosted GitHub Actions pass, or a prospective-merge validation. It does not prove the present interpreter, packages, machine state, or other external dependencies are identical to the historical environment. It also does not infer R31 Rust correctness, new pidfd fixture behavior, performance adoption, or private-source full-tree identity. Those require their separate original evidence.

Local validation consisted of Python syntax parsing and one successful execution of this read-only verifier. No CI gate, archived producer, benchmark, or remote operation was run.
