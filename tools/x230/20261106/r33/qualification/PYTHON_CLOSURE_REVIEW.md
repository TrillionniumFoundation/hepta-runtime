# R33 published Python input closure

The actual PR #99 source commit `2e2057d1af4d0205ee84933484beb5d598d72fe1` preserves **all 85 inputs / 1,862,543 bytes** from the verified historical Python closure. Every expected Git blob ID, mode and byte count matches both accepted R24 and the published candidate. The branch head was read back at that same commit during this review. Full per-path comparisons are in [python-closure-published-review.json](python-closure-published-review.json).

| Binding | Accepted R24 | Published R33 |
|---|---|---|
| Commit | `baab4def80be7af015b2e7a594cb302f66c4130e` | `2e2057d1af4d0205ee84933484beb5d598d72fe1` |
| Root tree | `b74e40052e275abe99c51df460e94622d516af34` | `a010c744b35bffb92ea1d513c1d2b6dad7ebca5a` |
| Complete recursive entries | 9,048 | 9,142 |
| Independently reconstructed tree objects | 827 | 847 |
| Tree-object mismatches | 0 | 0 |

Tree objects were reconstructed from Git's mode/name/NUL/child-object byte representation, including Git name ordering. Both recursive inventories were untruncated. The three original unittest discovery directories also retain their entire original subtree IDs and their exact discovered sets:

| Directory | Discovered files | Subtree and set match |
|---|---:|---|
| `tools/x230/20261028` | 8 | Yes |
| `tools/x230/20261029` | 1 | Yes |
| `tools/x230/20261030` | 2 | Yes |

## Historical execution being reused

The [frozen baseline comparison](python-closure-baseline.json) points to the [previous verified proof](https://github.com/TrillionniumFoundation/hepta-runtime/blob/b9cea9e4295280900b77514947fd02fedb8acdb7/tools/x230/20261105/r31/python-closure-reuse/proof.json). Its exact bytes were fetched and checked: 56,967 bytes, SHA-256 `14b5ca56194a1f33f50924dfef5bba7a67cdcbd452db5701fda9466e4bc6616e`.

That proof records original job `1a1ad72111c-fc05-59eb`, executed on 2026-11-05: **18 commands passed, zero retries**, with 36 original gate streams / 44,938 stream bytes checked. The 85-file manifest in the R33 baseline comparison is exactly the same manifest. This review binds that existing evidence to the actual published R33 tree.

## Boundaries

**No Python regression gate was rerun for this review.** The original historical archives and streams were not reopened; their prior verified audit is inherited. The historical SHA-256 values are retained, while this pass checks current Git object IDs, modes, sizes and discovery membership.

This is a finite 85-input closure. It does not re-establish every possible dynamic dependency, current interpreter/package/OS equivalence, hosted Actions success, prospective-merge success, Rust results or performance adoption.

The canonical published workflow belongs to the closure. The separately copied private SOURCE workflow remains a different artifact: it omits the 20261029 and 20261030 discovery commands in both jobs. This report makes no identity claim for the complete private SOURCE directory. The frozen proof retains that distinction.

Only Git reads, static tree hashing and report generation were used. No Mac/x230 request, source mutation, archived program execution or original auditor rerun occurred in this review.
