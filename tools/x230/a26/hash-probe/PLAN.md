# Frozen 16 KiB / 64 KiB full-file hash experiment

This is a standalone, read-only experiment on `/usr/bin/ssh`. It does not invoke
SSH, contact a host, modify runtime inputs, change a service, or modify the A26
runtime. Compile and run it only after the complete A26 series has finished.

## Fixed scale

The first complete read establishes the file stamp and reference SHA256. Then
run eight warmup reads with A (16 KiB), eight with B (64 KiB), and eight fixed
ABBA blocks. Each measured cell contains 128 complete reads and hashes: 32
measured cells and 4,096 measured full-file SHA256 operations. The order, scale,
and decision thresholds are fixed before measurement. Do not rerun failed or
unfavorable cells, select successful subsets, or tune the scale after observing
performance. These are repeated reads following the declared warmups; no page
cache eviction or cold-storage claim is part of this experiment.

Each iteration opens the fixed path with the runtime's no-follow descriptor
walk, verifies a regular root-owned single-link executable within the original
16 MiB bound, and rejects unsupported capabilities. Each opened descriptor's
stamp must match the reference before the full read. After the read, both that
same descriptor and a newly opened path must match the same reference stamp.
Every complete-file SHA256 must equal the reference. The stamp contains device,
inode, UID, mode, link count, length, mtime, and ctime, matching the runtime's
`Stamp` fields. Access time is excluded, as in the runtime.

The timed region contains SHA256 context creation, zero-initialization of the
fixed-size stack buffer, bounded complete-file reads, hash updates, and digest
finalization. Descriptor opens, metadata/capability checks, output formatting,
and JSON writes are outside that region. Thread CPU and wall duration are
recorded separately for every iteration; the whole cell's wall duration is
also retained. These are the same read/hash timing windows, with the fixed
clock-call and bookkeeping overhead of this probe; they are not pure SHA
instruction cycles. Interrupted reads follow the existing inner-loop behavior, are
counted, and do not restart a cell. A non-interruption read error, identity
change, digest mismatch, or clock error stops subsequent cells and is retained.

Raw JSONL retains the reference, both warmup cells, every measured cell, every
iteration's timing/read counts/hash/stamps, any failed partial cell, and the final
completion status. An incomplete or failed run has no performance decision.

## Predeclared decision

For each ABBA block, compute the arithmetic mean of its two A cell sums and
the mean of its two B cell sums separately for read/hash thread CPU and wall
time. For either metric, improvement percent is `100 * (A_mean - B_mean) /
A_mean`. Compute the median of the eight CPU improvements, the median absolute
deviation (MAD) of those eight percentages, and the median wall improvement.

Only an intact, fully successful fixed experiment can pass. All four gates
must hold: median CPU improvement at least **3%**; positive CPU improvement in
at least **7 of 8** blocks; median CPU improvement strictly greater than
**2 × MAD**; and median wall improvement at least **−2%**. Equality passes the
3% and −2% thresholds but does not pass the strict MAD comparison.

A pass means only that 64 KiB merits a separate runtime candidate and end-to-end
qualification. It does not establish a runtime throughput or latency gain,
memory improvement, concurrency behavior, or global optimum. Otherwise retain
the current 16 KiB buffer. A larger fixed buffer adds 48 KiB per active hashing
worker; with two active validation workers, the corresponding buffer-space
increase would be 96 KiB. All production authority checks would remain required.

## Build provenance and execution

`prepare_hash_probe.py` consumes the actual successful A26 qualification report
and independent receipt. It verifies their linkage and the recorded release
log hash, selects the unique `ring` and `libc` release `compiler-artifact`
records, checks their manifests against the qualified `Cargo.lock`, and records
the artifact hashes. No dependency is downloaded or chosen by a filename glob.
The probe uses those exact existing rlibs and the already installed actual
`rustc` executable for the qualified 1.95.0 toolchain. Before compilation, the
same toolchain's `rustfmt` formats only the fresh standalone source copy using
the qualified source's `rustfmt.toml` (including hard tabs). It does not modify
the qualified source or shared target directory. A fresh output directory
retains the unformatted `hash_buffer_probe.input.rs`, the formatted
`hash_buffer_probe.rs`, their separate hashes, formatter/config hashes, plan,
format/build commands and logs, build receipt, and any failure. The
`source_to_publish` receipt identifies the actual formatted source compiled
into the probe; publish that file. `--compile` is explicit; the script never
runs the probe. Formatting or compiling before the A26 series ends is outside
this plan.

The measured program reads only the fixed executable and emits JSONL to stdout.
`run_hash_probe.py` executes that exact compiled binary once in a fresh output
directory, independently hashes the target before and after the run, binds the
build receipt, and retains stdout, stderr, and the actual exit code. It never
retries a failed run. On interruption it sends SIGINT at most once through its
own subprocess handle and waits for that process's exit before collecting
evidence. `summarize_hash_probe.py` preserves the input JSONL
verbatim, checks the entire sequence and all receipts, and applies only the
predeclared rule. It does not execute the probe or retry any work.

After the complete A26 series ends, the intended commands are:

```sh
python3 prepare_hash_probe.py --qualification /absolute/A26/qualification/report.json --qualification-receipt /absolute/A26/independent.json --rustc /absolute/installed/toolchain/bin/rustc --output-dir /absolute/fresh/hash-build --compile
python3 run_hash_probe.py --build /absolute/fresh/hash-build/build.json --output-dir /absolute/fresh/hash-run
```

The paths are explicit operator inputs. The build and run directories must not
exist already; the runtime source and existing service directories are read
only. Omitting `--compile` creates a provenance/command receipt without invoking
the compiler; a later compile still needs its own fresh directory.

The earlier FD handoff idea remains deferred. Worker-side and owner-side checks
observe different times and cannot be merged as an equivalent optimization.
