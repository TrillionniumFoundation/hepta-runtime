# Publisher blocking capability: fresh build and immutable readback

Run only in GitHub CI:

```sh
python3 -I -S -B recipe/entry.py build --hepta "$HEPTA" --output "$RUN"
python3 -I -S -B recipe/entry.py read --capture "$RUN" --output "$READ"
```

The exact four runtime HIA images are publication, codec, errno and worker
lifetime. The actual HIA linker and packer are separately compiled, giving six
fresh compiles. The unchanged synchronous body source and adapter remain exact.
The native prefix has no runtime Python, libc or dynamically selected code.

Every compiler receipt, whole linker/packer input/output/workspace, native
object, ELF, source and bootstrap generation is retained. Four actual evidence
mutations and two complete relocations are checked without executing native or
Rust code. The guard rejects mutation, foreign reads, processes, ctypes and
mmap and compares complete before/after bytes and metadata.

The follow-up CI job restores the entire uploaded ZIP/TAR with all files,
directories, modes, nanosecond mtimes and xattrs, then runs the same passive
reader under a fresh guard. All phases retain their failures. Neither a fresh
build nor its readback establishes native application or public asynchronous
behavior. Those flags remain false.
