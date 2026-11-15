# Mac staging importer 02: exact observed upload locks

The original importer job `1a1b07fbf30-fc05-70ed` exited 1 at its first staging
inventory check, before parsing the archive or writing any of the 23 payloads.
Root's subsequent read-only job `1a1b0805edd-fc05-70f5` found the expected empty
directory tree, the original archive and importer, and exactly two extra files:

```
.hepta-lock-43ab8cc39e522dce1f636e3e
.hepta-lock-ea8fd5f905048ab8cd6d37bc
```

Both observed files were regular, empty, mode 0600, owned by UID 501, with one
link. Their names match the corresponding uploaded archive/importer basename
hash prefixes, as independently checked by root. The exact original failure
and inventory Git references are preserved in `revision-01.json`; they remain
under the original transport's `original-failure/` publication prefix.

Revision 02 permits only these two exact additional names. It opens them without
following links, requires empty regular files with current ownership, mode 0600
and one link, and requires their full stat identities to remain unchanged after
the import. No wildcard or general extra-file allowance is introduced. Before
writing, it also binds the retained original importer to its exact 14,918-byte
length and SHA-256. The archive, all 23 original file identities, USTAR parser,
size bounds, directory checks, O_EXCL writes, readback and fsync remain unchanged.

Upload the new importer outside staging, to this exact path:

```
/Users/qianqi/work/hepta-runtime-d1-c1-mac-importer-02.py
```

Then run exactly once:

```
/usr/bin/python3 -I -B /Users/qianqi/work/hepta-runtime-d1-c1-mac-importer-02.py
```

Keep the original archive, original importer, observed locks, and original empty
subdirectories in `/Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01`.
Nothing is deleted, moved, renamed, or overwritten. On success, use the unchanged
original `install_campaign.py` and its already reviewed exact Mac installation
arguments. Revision 02 does not invoke that installer or start any workload.

This fixes a transport precondition before the first diagnostic measurement; it
does not rerun a measurement. Local checks were AST parsing and exact source
comparison only. Eight original functions remain byte-identical. The six text
changes reverse exactly to the original importer. No importer or host command
was executed by this preparation task, and this static package does not claim
an actual successful import.
