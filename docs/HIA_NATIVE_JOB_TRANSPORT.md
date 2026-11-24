# Native job transport in the v26 HIA controller

The runtime can select a complete HIA implementation of START, READ, STATUS and CANCEL for a configured Linux host. The HIA installation owner supplies the configuration and the controller package. Rust transports bounded request frames and captures results; the lifecycle decisions remain in the HIA owners.

## Installed selection

A host selects this transport with its `native_jobs` object. All five fields are mandatory. Every field contains `executable` and `sha256`, rejects unknown fields, and binds the fixed role below.

| Host field | Controller role | Maximum image |
| --- | --- | --- |
| `entry` | `hia-job-entry` | 2 MiB |
| `submit` | `hia-job-submit` | 4 MiB |
| `observation` | `hia-job-observation` | 2 MiB |
| `cancel` | `hia-job-cancel` | 1 MiB |
| `launcher` | `hia-job-launch` | 1 MiB |

Paths must be absolute and normalized, with the exact role basename; digests must be 64 lowercase hexadecimal characters. The ordinary HIA Worker installation owner derives this object from the installed v26 controller receipt, manifest and captured images. Partial selections fail validation. Disabling execution does not invalidate the host's READ or STATUS selection.

The v26 controller contains exactly 19 roles. The previous 14 roles retain their individual bounds. The native job transport exports the five lifecycle images and the three existing terminal encoder, writer and supervisor images. It requires an admitted v26 release and refuses a v25 release.

## Image custody and the remote entry

Every operation admits all five configured pins against the selected controller release before preparing its target. The controller accessor checks the expected host digest against the manifest digest on every call. The first read verifies all four memfd seals, reads with `pread`, checks the content digest, and caches an immutable shared image. Concurrent reads share the same `Arc` and do not change the descriptor's cursor. Changing a pathname after release admission cannot replace these captured images.

The SSH command is the shell-quoted, administrator-selected `entry.executable` path with no caller-supplied arguments. This installed entry is part of the host's trusted computing base. Its own running identity is not established by hashing a pathname before execution. The entry checks the expected target digest, role, exact envelope and bounds, seals the received image and request, then invokes the fixed target with `execveat`. Public tool arguments cannot select another target path, target digest or arbitrary argument vector.

A native selection never falls back to the Python job implementation after a validation, connection, execution, timeout or decoding failure. Unsupported legacy/system-jobctl profiles are refused explicitly.

## Shared request framing

Direct SSH and the observation pool use one typed encoder and one target-admission path.

| Operation | Target protocol | Main fields |
| --- | --- | --- |
| START | `HIAJSB01` | Metadata, optional stdin, and the four original native images |
| READ | `HIAJOBQ1`, mode 0 / flags 0 | Bound job identity, two 64-bit offsets and byte limit |
| STATUS | `HIAJOBQ1`, mode 1 / flags 63 | Bound identity and all six existing native fact selections |
| CANCEL | `HIAJCQ02` | Bound identity, grace duration, authority/writer digests and images |

The outer `HIAJEX01` envelope has a 96-byte header, a fixed operation code, target image and payload lengths, and the expected lowercase target SHA-256. Its image is bounded by 4 MiB. START preserves the distinction between absent stdin and a present empty string. Its metadata preserves the original request and authority flags while replacing the three hex image fields with raw images and fixed publisher pins. The launcher and entry path come from the complete host selection.

STATUS requests require all six fact flags and an instantaneous remote snapshot. The existing HIA poller owns repeated observations and the external wait budget. Native-only requests outside that complete profile fail before SSH.

## Deadlines and observation admission

The absolute request deadline starts before frame construction and controller artifact admission. Direct calls retain the existing entry-guard and operation custody. Queued calls retain the existing leases, queue, cancellation, reaping and timeout ownership.

Observation commands, headers and mutable control payloads keep the original 64 KiB pool budget. The separately bounded, already admitted executable is an immutable shared image; queued requests do not clone a fresh executable allocation. The pool accepts only operation 2 frames, so START and CANCEL cannot enter an observation lane.

## Qualification scope

The native transport tests cover complete role selection, wrong or missing pins, exact role extents, sealed descriptor custody, path replacement, concurrent image sharing, descriptor cursor preservation, v25 refusal, exact 64-bit READ offsets, STATUS flags, and pool bounds. Existing direct/pool job regressions and actual public tool campaigns remain required.

The HIA source release separately qualifies job-entry framing, the launcher against its original runner, READ/STATUS/CANCEL against their original observation implementations, and START including real systemd behavior. These component gates are not a substitute for a fresh Worker installation and an end-to-end v26 public-tool campaign.
