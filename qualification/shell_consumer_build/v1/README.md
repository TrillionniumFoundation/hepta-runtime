# Shell consumer binding with unchanged HIA owners

This isolated successor to PR #135 fixes two observed host-identity failures.
PR #134's shell consumer rejected a prepared outcome library built against a
different runner's allocator. PR #135 completed its native cold build, all 11
native partitions and final collection, then its batch, JSON and system original
groups rejected the native capture because the old foreground DATA reader read
the new original-runner's libc instead of the retained native-runner bytes.

## Change

The shell partition creates a separately sealed `consumer-shell-build` directory.
It uses the admitted B3 and the exact unchanged HIA sources to compile the outcome,
foreground controller and foreground packer on the consumer. B1/B2/B3, the outcome
object, both foreground images, the adapter and bundle must remain byte identical
to the prepared build. Only the two host-linked manifest entries may change; the
static process/output members and every other module remain exactly prepared.

The complete original shell suite list still runs with its original 180 second
per-suite limits. The collector admits the exact two-entry substitution, re-reads
both original build proofs and carries that same binding into the original Rust
pipeline. There is no new completion flag or synthetic semantic qualification.

Foreground DATA admission checks the retained libc and loader bytes. Actual
foreground execution calls the new explicit live admission before execution,
before every original case and after the last case. The outcome owner's original
strict loaded-allocator gate is byte identical to the parent commit. Equal-version
different-byte allocator and loader inputs are rejected by the new controls.

No HIA, assembly, workflow, original suite domain, public route or budget is
changed. The public graph remains PR #135's 118 direct plus 8 packed images, 71
slots and 13 registered tools out of the 136-tool target. `binary_write` remains
unregistered. Full runtime replacement and removal of the old stack remain false.

## Actual local validation

Compiler source remains `d3e2c90173cf733e42b299d0c4274df4b593a12f` and B3 remains
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`. This local
validation reused that admitted bootstrap; it did not perform a new cold compiler
qualification or any original Rust execution.

| Original complete suite | Retained domain | Actual elapsed seconds |
|---|---|---:|
| `shell_outcome_state.py` | 78,083 semantic cases, 111 controls, 78,194 native entries | 76.566657066 |
| `shell_output_io.py` | 20 complete IO cases, including actual outcome calls | 13.107756908 |
| `shell_foreground_controller.py` | 20 semantic cases, 84 controls, 810 native entries | 1.386357410 |
| `shell_foreground_io.py` | 12 original actual OS cases | 19.250627599 |

The fresh local build performed seven prepared and three consumer compilations in
11.738873384 seconds, with 413 prepared files unchanged. The original 55 pipeline
controls plus six new controls passed together: 61 tests, process exit zero,
10.959429081 seconds. Their materialized historical58 source includes all 2,176
source paths from the original PR #134 CI snapshot; no old path is missing. Its
2,197 current entries add PR #135's 19 retained proof files and the new helper/test.
The only changed common entries are this patch's five source edits and PR #135's
already-published historical profile/materializer updates.

The final DATA read passed in 36.927388158 seconds with 7,819 before/after entries
unchanged. The frozen guard retains its 11 rejection probes. A narrow wrapper
declares the four exact original reader input binaries (`as`, `objcopy`, `ld`,
Python) and binds read-only file descriptors to their actual opened inode and
metadata. Additional controls reject an unlisted tool, an unbound descriptor and
a stale descriptor. These are byte reads; the wrapper grants no execution access.
The original static readers still require those mechanical tool identities.

Earlier attempts are retained: the bundled Python lacks `F_SEAL_WRITE` and stopped
before loading the native owner; the first strict DATA wrappers rejected the
original readers' undeclared tool/descriptor inputs. No captured HIA or semantic
result was edited to resolve those harness failures. System Python 3.13.5 has the
original required memfd sealing constants and ran the complete four suites.

## Inspect the exact change and retained evidence

`SOURCE_CHANGE.json` carries exact forward/inverse line ranges for all five edits,
the two added source pins, 715 unchanged HIA/assembly/outcome file identities, and
12 unchanged gate/domain function identities. From this repository root:

```sh
python3 -I -B qualification/shell_consumer_build/read_source.py --root .
```

`RESULTS.json` binds the actual build, suite, complete-source and pipeline-control
records. `EVIDENCE.json` binds every archive part and every logical captured byte.
The chunk archive contains the full successful and failed local captures, complete
process outputs, source inputs, compiler dependency source, original PR #134
failure evidence and the three complete PR #135 failure logs. PR #135's seven
already-published archive parts are referenced by exact parent identity instead
of duplicated in this archive.

```sh
python3 -I -B qualification/shell_consumer_build/v1/restore_capture.py \
  --output /tmp/hia-shell-consumer-restored --parent-checkout .
```

Restoration verifies and restores bytes and modes into a new directory. It does
not rewrite recorded origins or pretend to reproduce recorded inodes. The
original semantic readers keep their original-location checks. At the retained
capture origin, the complete DATA command is:

```sh
/usr/bin/python3 -I -B qualification/shell_consumer_build/v1/read_current_capture.py \
  --capture-root /workspace/scratch/3aed38e33c2e/runtime-audit/allocator-next \
  --output /tmp/hia-shell-consumer-data-read.json
```

The independently verified normal CI remains the authority for new cold, complete
native and original Rust conclusions at this successor's actual commit. Local
validation does not label pending CI successful. No workflow gate was bypassed,
and no additional manual long Rust run was requested.
