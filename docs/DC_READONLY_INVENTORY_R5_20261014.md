# Desktop Commander successor — bounded six-host inventory, R5 (2026-10-14)

This is a product-facing, READ-ONLY diagnostic, not a DC retirement gate.
It reconciles existing Hepta controller records with target-owned request,
terminal and output receipts. It does not open shells, start jobs, cancel
operations, send PTY input, change permissions, repair databases, or delete
unknown files.

## Usage and protections

Use the configured operator account and a NEW private output directory.
For an explicitly configured six-host deployment, invoke:

    python3 -B deploy/dc_readonly_inventory.py \
      --config "$HOME/.config/hepta-runtime-operator/runtime.json" \
      --output "$HOME/hepta-runtime-inventory-snapshot-UNIQUE" \
      --hosts main,pocket4,rog,mac,x230,ai395

The only remote helper is deploy/inventory_host_readonly.py, sent via the
existing pinned-key SSH aliases. The interface does not permit a
per-request remote command. SSH target aliases cannot start with '-'
or contain whitespace/options. The existing config is opened with
O_NOFOLLOW and its owner, length and exact identity are rechecked.

Bounds: 16 hosts, two simultaneous SSH calls, 16,384 source entries per
directory, 1 MiB per metadata record, 64 MiB total metadata, 8 MiB SSH
stdout, 64 KiB diagnostic stderr, and bounded target observation time.
The client drains stdin, stdout and stderr in nonblocking bounded streams,
never into unlimited subprocess.communicate buffers.

The collector binds every controller record to the configured target,
reads target metadata through safe file descriptors, rechecks original
hashes and membership after the host scan, and distinguishes successful
completion, failures, timeout, cancellation, and missing/unknown receipts.
It refuses duplicate JSON keys, hostile paths, target mismatches, changed
metadata, oversized streams, mismatched host rows, and identity reuse.
There are no automatic retries. Private output is created as 0700 root
and 0600 files, without overwriting historical snapshots.

An optional --dc-identity PID:START_TICKS asks only whether a particular
historical DC process identity is currently present; it never authorizes
stopping or signalling that process.

## Qualification of this exact helper and collector

- 37 host metadata tests and 17 bounded collector tests passed, including
  an actual local helper process under a fixed fixture SSH adapter.
- The final real six-host cohort returned 9,017/9,017 selected job and
  PTY records, with no requested IDs missing or duplicated.
- Main: 4562; Pocket4: 875;
  ROG: 522; Mac: 1352;
  X230: 309; AI395: 1397.
- Jobs: 8,002 succeeded, 818 failed, 33 timed out, 22 cancelled,
  two missing exit receipts and one unknown. PTY: 138 exited, one
  without its final exit receipt.
- 9003 records independently matched
  output-size counters and explicit complete-output receipts. Log contents
  were not read or re-hashed, so this is NOT all-log-content integrity.
- Controller record hashes and membership stayed stable for this bounded
  observation window. Private report SHA256: 0b3046ddb7ede5e38212cadd6dc74d4b9f8ea7e82c4a1904173b9eee3992e58e.
- The two previously registered Desktop Commander SSH process identities
  were still present. The old zero-byte publisher temporary remained.
- Source hashes: collector 883254f7f37fa5dcb9c8d9b08ac69baaddd127e9681947334f42967709fe7751; host helper 368e22815101534070aec400a61811e3bb687ff1b323155169c5321e541f785b.

## Deliberately remaining unknown

The original Pocket4 job 1a13940afd5-b2f-10ec has a local recorded
launch_failed result caused by an SSH TCP connect timeout 255; the original
target job directory is absent. No automatic replay is authorized. The
original X230 terminal dpty-9f7edeb169f9b85b36765470b73734946e3111b6a1e461f3b73e03f73ab2c925
belongs to an earlier host boot; its owner is absent, 24 archived bytes
remain without an exit receipt, and it is still lost.

Five target roots were group-writable (0775), Mac root was 0755,
and no source-root integrity qualification has been established. The
inventory job itself is naturally running while scanned. A bounded stable
read-only scan is not a global admission freeze or future-write exclusion.
This candidate does NOT provide ChatGPT caller isolation, model-origin
tool catalog Refresh, DC stream adoption, proven business custody or a
real production DC-off rollback. It never reports safe DC retirement:
can_retire_desktop_commander=false and full_replacement_qualified=false.

All historical files and the existing V4/DC business services remain
unchanged. The repository contains only source, synthetic tests and a
sanitized hash/count record; raw private evidence stays on the host.
