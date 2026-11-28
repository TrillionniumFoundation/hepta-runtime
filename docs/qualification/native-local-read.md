# Native-local read qualification

The seven-image HIA read profile implements `binary_read`,
`read_multiple_files`, and `file_info` for the explicit `native-local`
host and startup root. It is separate from the current default runtime graph.
A pass here does not establish configured SSH host support, the default public
routes, writes, or replacement of the full runtime.

## Reproduce

Use the Hepta compiler commit pinned by `scripts/hia_native_build.py`.
The runtime Git object database must contain the original commit declared by
the three component composition records:
`a0dcdda1991ec536d5e2d252c006a778993fa566`. A shallow checkout can obtain it with
`git fetch --depth 1 origin a0dcdda1991ec536d5e2d252c006a778993fa566`.
No network operation is performed by the qualification script.

```sh
python3 scripts/hia_native_local_read_qualification.py \
  --hepta /absolute/path/to/pinned/Hepta \
  --build-root /absolute/path/to/owned/read-qualification
```

The command builds the actual static ELF and runs the three existing service
suites against real files, including metadata, xattrs and a POSIX ACL. It saves
`qualification.json`, individual results and stdout/stderr beside the build.
The ACL fixture filesystem must support the exercised metadata operations.

The tested HIA, parser, packer, builder and test source identities come from the
current source tree. Original Rust and Python reference files come from the
declared historical commit and must retain every existing Git blob and SHA256
binding. Changes to current Rust sources therefore cannot silently substitute
a new original oracle, and do not force the current HIA to use an old checkout.
The reference files are test inputs only; the produced ELF has no Python or
libc dependency.

The suites accept `HIA_RUNTIME_REFERENCE` as a separate original source root.
Their existing defaults continue to support original-source checkouts.
The qualification entry point materializes and verifies this root and verifies
both the current inputs and original files again after execution. Missing Git
objects, a wrong commit, changed reference files, a failed suite, or a changed
input produces a failed report and a nonzero exit code.

Run the independent reference-isolation regressions with:

```sh
python3 tests/hia_native/test_local_read_reference.py
```
