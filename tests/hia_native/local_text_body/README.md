# Independent Local text body fixture

This gate builds the final private Local `str_replace`, `delete_file_spec`, and
`undo_edit` composition. It has twelve HIA members and a separately compiled HIA
packer. The emitted Linux x86-64 executable requires neither Python nor libc.
Python and Rust are explicit qualification tools.

The four new semantic sources live in `fixture_native` for this independent
gate. In particular, the metadata-capable `local_read` is not installed over the
aggregate runtime owner by this change. Promotion requires rebinding every
shared read descendant and rerunning its original complete gate.

## Source and ABI

`component.json` fixes all twelve source and image identities, the callable and
stdio assembly sources, the complete prefix, and the final 2,304,951-byte ELF
with SHA256 `3a10f516263bc13ad78f931690fdde6c28d6aa8e83c7f2815b66956fb00d016e`.
`CALLABLE_ABI.md` specifies the 192-byte caller context, retained result,
run/resume/cancel-wait/release entries, shared history/lock ownership, cache and
hint callbacks, and their lifetime obligations. Child 10 is the hint callback;
the last two images occupy child 11 and child 12.

The compiler remains Hepta commit
`d3e2c90173cf733e42b299d0c4274df4b593a12f`. This focused recipe checks its tracked
source closure and constructs the matching B1/B2/B3 fixed point. It does not
replace the complete compiler cold gate required by aggregate qualification.

The original fixture contains 74 byte-exact items from nine complete target
files at commit `d3d75c30719db966b004756f610007a7c723729e`. Its minimal locked
reference uses Rust 1.95.0 and target Tokio 1.53.3. Every CI run builds a fresh
locked target directory and binds the actual resulting executable to the
subsequent captures; an old development binary hash is not used as a substitute
for that build.

## Complete retained domains

| Domain | Required scope |
| --- | --- |
| Read compatibility | 384 old/new cases, 15 namespace refusals, 21 metadata cases, 4,808 actual calls, complete output and workspace bytes |
| Callable capabilities | 25 groups, 45 export calls, 11 explicit owner calls, 82 complete blobs; real lock wait/resume/cancel, borrowed lifetime, callback and allocator refusal |
| Ordinary bodies | 68 original/native process pairs, 129 operations per side, unchanged 60-second process and 180-second complete-capture bounds |
| State evidence | All responses, hints, complete cache/history/lock arenas, raw filenames, file bytes, modes and hardlink groups |
| Observer refusals | All 39 original/native byte-mutation controls, recomputed by the final read-only admission |

The ordinary corpus preserves history-before-write and pop-before-undo-write
failure behavior, the ten-snapshot limit and stale queue order, poisoned maps,
context absence, aliases, permissions, large content, and the difference
between bare-relative and parent-anchored deleted paths. The corpus and both
full-state decoders retain their previously qualified bytes.

Only fixture/build admission is adapted for relocation. After a successful
complete readback, exact owned live fixture directories are archived as raw-name
metadata plus their complete content blobs, checked again, and retired. Cyclic
or dangling fixture links therefore never enter the aggregate artifact walker.
No root-wide source glob or hardlink snapshot is used for evidence admission.

## Run

```sh
python3 -I -B scripts/qualify_hia_local_text_body.py \
  --hepta /absolute/pinned-Hepta-checkout \
  --toolchain /absolute/rust-1.95.0-toolchain/bin \
  --output /absolute/new-output-directory --phase all
python3 -I -B scripts/qualify_hia_local_text_body.py \
  --output /absolute/new-output-directory --phase verify
```

Run Rust builds and original comparisons on the designated development host or
CI, as required by the repository instructions. `--phase native` is available
for native build and capability work; it deliberately does not claim the
ordinary original comparison passed. The checked-in workflow runs the complete
recipe against an independently checked-out original source tree.

## Limits

The fixture is Local and finite. The ordinary replacement cohort uses admitted
nonempty needles. Separate native guard refusals for unsafe original boundaries
are not counted as successful original parity, and targeted crash or
nontermination reproduction is not part of this gate. The explicit lock-wait
controls do not qualify arbitrary I/O-await cancellation, Tokio scheduling, or
runtime shutdown. Public TextEditor routing, whole-runtime replacement and old
stack removal remain false in every report.
