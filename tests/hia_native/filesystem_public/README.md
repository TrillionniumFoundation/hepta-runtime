# Public filesystem capture and admission contract

The twelve Python source files in this package are test producers and readers.
They do not implement a production filesystem handler or compute a substitute
tool response. The supplied public and private ELF files contain the shared 58
HIA images; the build reader independently admits their compile, link, pack and
source records. Cold bootstrap remains a separate qualification.

## Native phase

Invoke `native_capture.py` with absolute values for `--reference-source`,
`--reference-reader`, `--native-source`, `--native-build-result`,
`--fixture-build`, `--public-build`, `--fixture-binary`, `--public-binary`,
`--output` and `--strace`. The reference source is the exact seventeen-file
materialization admitted by the frozen original reader; it may live below the
current output directory. This phase never reads original responses or runs
Rust.

`--native-build-result` is a mechanical binding of the two admitted manifests:
`source_binding.files` and `executables.{public,fixture}` contain their actual
source, manifest and ELF paths, sizes and SHA256 values. Constructing this
binding does not constitute another build.

The capture contains 28 private observation processes and 26 ordinary stdio
processes. The former cover all 323 public attempts and nine separate fixture
controls; the latter cover the 26 scenarios with one session. One actual
`strace -V` process is recorded separately from these 54 native ELF processes.
The complete selected tracer binary and version streams are retained.

Pure admission API:

```python
strict_native.native_evidence(
    native_capture=..., reference_source=..., original_reader=...,
    producer_source=..., native_source=..., build_reader=...,
    build_primitive=..., artifact_reader=None,
)
```

It returns `hepta.runtime.filesystem-sdk-native-evidence.v1`, with
`original_comparison_complete=False`, `original_capture_read=False`, the full
`artifact_sha256` map, and `fixture_origin`. No original capture argument is
accepted. Save this complete object for the next phase, including all source,
stream, process and build identities.

`transient_fixture_directories` is `['fixtures']`, relative to the supplied
native capture directory. Only this live fixture may be archived and retired
after native admission. Evidence files and their original execution paths must
remain unchanged. All readers are pure and never restore a fixture.

## Original phase

Restore the admitted owned fixture at the exact `fixture_origin` using the
pipeline's verified archive mechanism. Restore ownership and filesystem shape
under an explicitly owned destination; do not obtain access by substituting
path strings in either inputs or expected responses. Fresh original scenarios
perform their actual setup and run at the same recorded absolute cwd.

Invoke `replay_original.py` with `--reference-source`, `--reference-reader`,
`--native-capture`, `--native-admission`, `--output`, `--cargo`, `--rustc` and
`--strace`. The native capture argument is the current location of the saved
capture; its original fixture origin remains in the actual receipts. This
distinction allows a native shard and the aggregate job to use different output
roots without rewriting provenance.

The replay preserves invocation paths, including a selected tool's symlink
name. It records the resolved binary separately and retains full copies of
rustc, cargo and strace. Their actual version processes, full byte hashes,
commands, environment, streams and Cargo compiler observations are admitted.
Rust must report 1.95.0 and the x86_64-unknown-linux-gnu host; Cargo must report
1.95.0. The original locked dependency subset and source are unchanged. No
ai395 path, strace package hash, sysroot path or service cgroup name is required.

There are 32 actual recorded commands: three versions, one fresh locked Cargo
build and 28 original scenario replays. Each retains its actual 180-second
budget. The outer pipeline must separately retain its actual command, cwd,
PID, deadline and complete output through its normal process recorder; these
records are not replaced by invented durable-job metadata.

The replay binds every native predecessor file and the entire saved native
admission object before executing Rust. Both phases preserve their actual boot
ID and monotonic interval. Clock ordering is checked additionally when boot IDs
match. Different machines' monotonic values are never compared. The final
reader independently recomputes the whole native admission and requires exact
equality with `NATIVE-ADMISSION.json` retained by the original replay.

## Complete admission

```python
strict_native.evidence(
    native_capture=..., original_capture=..., reference_source=...,
    original_reader=..., producer_source=..., original_driver_source=...,
    native_source=..., build_reader=..., build_primitive=...,
    artifact_reader=None,
)
```

The `artifact_reader(Path) -> bytes` callback maps the build's recorded paths
to verified archived artifacts. Capture and source arguments are their current
physical roots. No fallback to former execution roots is necessary.

This admission compares complete original replies, session and cache state,
within-run filesystem identity relationships, actual syscall order and native
continuation/effect receipts. The two native transport domains are counted
separately. Private close mode is not presented as an ordinary OS BrokenPipe.

`strict_original.reference_evidence(reference_source, original_reader,
driver_source, native_capture, original_capture)` remains a pure original
receipt/stream admission. It explicitly does not itself admit native HIA
semantics. Production qualification must consume the complete API above.

## Refusal and relocation suite

`test_native_evidence.py --plan PLAN.json --output NEW_DIRECTORY` runs only
Python readers. The plan has the same nine keyword paths as complete admission.
Its six groups contain 42 physical refusals: process contract 8, receipt and
continuation semantics 13, observer state 6, source/build/predecessor identity 8,
files and typed JSON 5, and whole streams 2. All earlier 36 controls remain;
six additional controls cover selected tool bytes, tracer command, boot ID and
complete predecessor bindings.

Both relocation children deny access to former execution artifacts. Native-only
admission additionally denies all original-output opens. The first relocated
root is actually renamed away before the second admission. The complete native
and native/original evidence objects must remain identical, with no live
fixture, HIA execution, Rust execution or compilation during these checks.

## Explicit scope

This corpus does not claim an original complete JSON-RPC router or config
loader execution, remote I/O, full configured fence acquisition, the additional
67 MiB op8 domain, a complete lease-record array, or individual original
notification intervals. The original 323-attempt contract and nine private
controls are not enlarged by the build's additional capabilities. Separate
evidence is required for those domains.
