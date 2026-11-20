# Retained binary-write DATA reader recovery

The full frozen private binary-write domain is readable: **101/101 inputs in
35/35 original capture groups PASS**, covering **103 original and 103 native
entry invocations**. The recovery executes no original application, native
application, or compiler. It keeps the original 180-second reader budget and all
11 read-only denial probes per input (1,111 probes for the complete domain).
`RESULT.json` records the exact source and reader pins, counts, and limitations.

## What changed

1. The Linux x86-64 descriptor reader recognizes `fcntl(fd, F_DUPFD, ...)` and
   `fcntl(fd, F_DUPFD_CLOEXEC, ...)`, alongside `dup`, `dup2`, and `dup3`. It does
   not classify other `fcntl` operations as duplication. Only a successful
   syscall creates a descriptor. The control-FD move must occur in its recorded
   command-17 exchange and precede the actual successful close of FD 0.
2. The closed-parent filesystem comparison binds the observer path to the
   captured process PID, matching the kernel trace start, and the recorded
   caller-owned parent FD. Only the complete `/proc/<bound-pid>/fd/<bound-fd>`
   path and its complete ENOENT diagnostic receive a process-identity label.
   Other PIDs, FDs, suffixes, embedded paths, and error messages stay literal.
3. The DATA reference uses the captured CPython 3.12.3 strict Base64 semantics.
   Host CPython 3.12.14 rejects `AP8Q====`, while the frozen 3.12.3 input domain
   and both retained applications accept it. `base64_3123.py` fixes the DATA
   reference semantics using the upstream 3.12.3 algorithm. It compares complete
   successful bytes and exact exception classes/messages, including non-ASCII
   input. It does not run a captured binary or import a captured native module.

The three `.patch` files show every change to copies of the original readers.
All remaining original reader modules are loaded from the immutable reconstructed
source bundle. The original `actual/` sources, HIA bytes, binaries, inputs, kernel
captures, event trees, errors, and filesystem observations are unchanged.

## Evidence and original failures

Original source commit: `ecc2076ab7537e2a637480769c7e3bb1403941e0`.

Original source manifest SHA-256:
`5a4adda7189b444d5451381e815eaf7defdc4db0e42b77b222c9c630e8f3eb57`.

Original capture workflow:
<https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/44196697861>.

All 202 retained original/native processes completed successfully, with 103
entry invocations per role. The original group-19 gate remains **FAIL** because
its old DATA reader rejected cases 53, 54, and 55. The other 34 original gates
remain PASS. The retained recovery is a separate result; it does not rewrite
those historical outcomes.

The first complete recovery attempt also remains recorded: it passed 100 inputs
and exposed the host-Base64 version drift on case 5. Its failed process, complete
stderr, summary, and exact reader bytes are retained in the evidence archive.
After fixing the reference semantics, the complete 101-input domain passed.

`evidence.tar.xz` contains complete final read reports, process records and
stderr, all 35 archive receipts, the original successful application process
receipts, original group gates, regression controls, original failure records,
and the exact executed reader/driver sources. `EVIDENCE.json` binds the complete
archive bytes and the internal manifest binds every member. No signed download
URLs or credentials are included.

`ARTIFACTS.json` identifies all 35 original ZIPs by artifact ID, source/run,
size, SHA-256, and expiry. Their total size is 5,845,014,673 bytes. Each ZIP,
exported TAR, object, reconstructed file, and mode was reread against its bound
identity before the DATA comparisons. The original ZIPs remain in GitHub Actions
under the listed retention dates; this change does not duplicate them in Git.

## Reproduce from retained artifacts

Download the original Actions artifacts identified by `ARTIFACTS.json`, keeping
the exact ZIP bytes. Use a new output location for each group. From this directory:

```sh
python3 -I -S -B unpack_retained.py --zip /captures/19.zip --group 19 --output /recovery/groups/19
python3 -I -S -B read_retained.py --source /recovery/groups/19/source --work /recovery/groups/19/run --case 53
python3 -I -S -B test_reader_repair.py --source /recovery/groups/19/source --work /recovery/groups/19/run
```

Materialize groups 0 through 34 by their corresponding ZIPs. Then run the complete
frozen domain, with at most three concurrent DATA readers:

```sh
python3 -I -S -B read_all.py --groups /recovery/groups --output /recovery/reports --jobs 3
```

The commands parse and compare retained data. They never build or replay the
application. `read_all.py` retains per-input reports and exits nonzero if any
input fails or reaches its unchanged timeout. Its `SUMMARY.json` must show
101 passes, 103 invocations per role, and 1,111 guard probes.

Regression controls use six real captured roles from cases 53–55. They also
reject failed duplication, F_GETFD/F_SETFD masquerading as duplication, wrong
PIDs/FDs, path suffixes, embedded paths, changed errno, and a receipt PID that
contradicts the kernel trace. Eight exact Base64 success vectors and sixteen
exact error vectors cover the version-sensitive reference boundary.

## Scope

This closes the retained DATA-reader qualification of the private callable
binary-write body within its frozen 101-input domain. Public `binary_write`
routing, parent-path policy, SSH, upload, and full runtime replacement remain
outside this proof. `whole_runtime_replaced`, `production_activated`, and
`old_stack_removal_qualified` remain false. The Rust/default-stack deletion gate
is unchanged.

The Base64 reference derives from CPython v3.12.3
[`Modules/binascii.c`](https://github.com/python/cpython/blob/v3.12.3/Modules/binascii.c)
and the string conversion in
[`Lib/base64.py`](https://github.com/python/cpython/blob/v3.12.3/Lib/base64.py).
The source SHA-256 is recorded in `RESULT.json`; its license is retained in
`COPYING.cpython-3.12.3`.
