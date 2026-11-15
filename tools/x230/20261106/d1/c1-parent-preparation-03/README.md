# D1 C1 diagnostic outer campaign — unsealed preparation revision 03

This package prepares the first D1 C1 campaign. It has not run the holder,
parent, adapter, binder, native auditor, compiler monitor, sealer, installer,
Rust, a compiler or any remote request. Actual D1 qualification, native exact
CI, formatted source map and retained feature ELF identities are absent from
the executable parent and adapter until the later seal. The current
qualification launch is a fact recorded outside this source preparation; its
future outcome is not assumed here.

D1 is based on accepted R24 plus the reviewed opt-in diagnostic patch: 13
changed compiler inputs, including 2 new files, giving 222 inputs. R35 supplies
only its already closed cache. Its normal lifecycle regression remains a
rejection; this diagnostic campaign cannot adopt R35, D1 or another candidate.

## Fixed experiment

One actual, original all-features qualified ELF is used in all four rounds.
The mode order is OFF, ON, ON, OFF. Only concurrency 1 is authorized. Each
round retains the original 6 preflight requests, 24 warmup calls, 192 measured
calls and 12 restart requests. The original driver creates first and restart
controllers, giving eight original controller lifecycles and eight private
sidecars. Planned totals are 768 measured calls, 96 warmups and 72
preflight/restart requests, or 936 requests. These numbers are the fixed
protocol, not a claimed result.

There are two child stages:

1. The unchanged original R16 wrapper/benchmark/resources/allocator code,
   called through the independently reviewed adapter03. The adapter only adds
   three diagnostic variables at the original child-environment hook. It
   does not replace Popen, Controller, cell, main, close or the process reaper.
2. The byte-identical original native observation analyzer and its two
   original audit dependencies. Its source uses report.concurrency and
   calls_per_cell dynamically, so C1-only needs no source change or relaxed
   audit condition.

No boundary, cancellation-recovery, normal lifecycle, reserve-capacity or
production performance-adoption gate is scheduled. This is a diagnostic
stage, not the earlier three-concurrency optimization acceptance matrix.

The original held-agent source is byte-identical (11374 bytes,
715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65).
The parent's 18 reused top-level helpers, four nested helpers (including the
4734-byte owned-stage supervisor), 90-second quiet block, compiler monitor
sources, limits and policy are preserved. Historical R26/R35 schema names in
the reused monitoring/holder sources are provenance, not claims that an old
campaign ran again. The old policy's matrix wording describes the unchanged
monitoring component; the D1 C1 selection above is explicit.

## Mandatory failure-continuation clarification

The frozen pre-execution-clarification-01.json is required by SHA before
sealing, installation and execution. It preserves the original driver:
each measured cell completes its fixed count, and a measured failure row does
not introduce a new per-call stop or cancel the original later-round behavior.
Any such failure rejects the whole stage, prevents a successful trace-cost
interpretation, permits no automatic retry and does not authorize C8.
Exceptions, warmup failures and cleanup failures stop as the original main
already specifies.

This is root's pre-execution correction to the earlier diagnostic plan's
suggestion to stop all later cells on the first error. The earlier source
plan remains unchanged. No save_report interruption hook or new reaper was
added.

## Input and source binding

d1_prerequisites.py is the exact same source deployed separately for native
exact CI. Its Q-only entry consumes the independent
qualification-prerequisites-01.json, so CI never depends on its own future
success. The full entry requires both actual Q and actual native CI closure
and real original raw read pages. It does not synthesize combined native
receipts. Dynamic counts derive from the actual isolated summary/audit and
the actual nextest inventory.

The full campaign foundation is first supplied to the sealer as a separate
staged input, for example:

    ROOT/c1-parent-preparation-03/actual-prerequisites-01.json

The campaign destination ROOT/c1-prerequisites-01.json must remain absent
until its first installation. The binder takes the already bound JSON body,
so it does not require that destination before the seal.

The binder verifies the original eight all-features qualification stages,
nineteen original harnesses, full formatter/input/tested map, all 222 current
compiler inputs including embedded Python, the retained three release
programs, real native terminal/read pages and the original nextest0.9.137
six-stage exact-CI evidence. The prior R35 owner proof is rebound after the
recorded rename; the old migration-time cache_owner_closed function is not
rerun against a cache that has already moved.

It does not claim current machine quiescence or hosted GitHub Actions success.
Ordinary cfg supplementary builds are separate and cannot replace the
qualification feature ELF. The full source and original tool inputs are
rechecked around the campaign.

## Fixed fresh namespaces

ROOT is /home/qian/hepta-runtime-phase-cost-20261106-d1.

| Purpose | Fixed destination |
| --- | --- |
| Linux runtime tools | ROOT/c1-tools-01 |
| Full actual prerequisite foundation | ROOT/c1-prerequisites-01.json |
| Parent input receipt | ROOT/c1-campaign-inputs-01.json |
| Parent output | ROOT/c1-campaign-01 |
| Original native output | ROOT/c1-observation-01 |
| Adapter evidence | ROOT/c1-adapter-evidence-01 |
| Short socket parent | /home/qian/hd1c01 |
| Mac source directory | /Users/qianqi/work/hepta-runtime-d1-launchers-01 |
| Mac held-agent output | /Users/qianqi/work/hepta-runtime-d1-c1-holder-01 |

The parent creates the short socket parent once, after the original quiet
period and immediately before the native stage. It never removes an old
directory. The adapter requires this existing, empty, owned private directory.
Neither the sealer nor installer pre-creates benchmark, adapter, socket or
held-agent result namespaces. A collision or partial installation must be
preserved and reconciled; no blanket cleanup or in-place retry is provided.

## Later sealing and installation

Only root may schedule host calls. These are future operator steps, not
commands executed by this preparation.

First stage this exact source package at a new preparation directory on x230.
After original Q, native exact CI and any independently authorized compiler
work have actually closed, supply a complete real prerequisite document.
The sealer runs only stable readers and the read-only binder. It neither
invokes Cargo nor starts a child, holder, monitor or measurement.

    /usr/bin/python3 -I -B ROOT/c1-parent-preparation-03/seal_campaign.py \
      --prerequisites ROOT/c1-parent-preparation-03/actual-prerequisites-01.json \
      --output ROOT/c1-sealed-01

Sealing verifies the frozen package manifest, binds actual Q/CI and the
current source/ELFs, and writes a new staged package. The sole executable
changes are the adapter's SPEC assignment and parent's ACTUAL assignment.
Their remaining ASTs must be identical. The output contains 18 Linux payload
members, 2 Mac payload members, a seal-manifest.json, operator-argv.json and
the installation-only script. Stdout identifies the actual seal manifest
bytes/SHA, parent and adapter. No actual measurement is claimed.

Copy the staged seal package as original bytes to a fresh private staging
directory on each destination. The two installers require the actual
seal-manifest SHA produced above:

    /usr/bin/python3 -I -B <sealed-directory>/install_campaign.py \
      --sealed-dir <sealed-directory> --manifest-sha256 <actual-SHA256> \
      --target x230

    /usr/bin/python3 -I -B <sealed-directory>/install_campaign.py \
      --sealed-dir <sealed-directory> --manifest-sha256 <same-actual-SHA256> \
      --target mac

The installer validates all 20 sealed payloads, exact fixed names and core
identities before its first destination mutation. It uses bounded owned
single-link regular-file reads, nofollow/O_EXCL creation, file readback and
file/directory fsync. Bounds are 4 MiB per member, 16 MiB total and 128 members.
It writes only the selected platform's 18 or 2 payloads plus an installation
receipt. No compiler, runtime, SSH or campaign is invoked. Failed partial
output remains intact and the original native installer result must be kept.

The Mac operator invocation in operator-argv.json is:

    /usr/bin/python3 -B \
      /Users/qianqi/work/hepta-runtime-d1-launchers-01/held_agent_campaign_02.py \
      --remote-script /Users/qianqi/work/hepta-runtime-d1-launchers-01/d1_campaign.py \
      --out /Users/qianqi/work/hepta-runtime-d1-c1-holder-01 \
      --timeout-seconds 3600

The unchanged holder hashes the exact parent it transmits over stdin.
The parent binds that SHA to its fresh input receipt and the separately
installed identical parent bytes. Its original campaign budget remains
3300 seconds, with the original cleanup reserve. Root alone launches this
once after all prerequisites and review are closed.

## Evidence and limits

The compiler monitor guards the prerequisite body, quiet period, original
child cleanup and final input/source checks. Its original final validator
can turn parent success into failure. The diagnostic summary explicitly
requires the final parent report and original holder/native closure; it is
not sufficient alone.

Sidecars are read, hashed and parsed only after the original four-round
matrix and all eight ordinary closes complete. Synchronous event costs are
joined to original native request IDs and original request intervals.
Preflight, warmup, measured and restart requests remain separate categories.
Whole-controller CPU and overlapping wall spans are not treated as additive
exclusive CPU for 192 measured requests. OFF traces do not invent event CPU.
The original raw transport/resource evidence remains the basis for the
independent native audit.

The original Controller constructor has an existing post-Popen exception
window before normal ownership is returned. This adapter does not alter that
constructor. Missing cleanup evidence stays unknown, prevents successful
trace interpretation and blocks a successful next stage; owned stage-group
absence alone is not proof that separate controller sessions have closed.
There is no automatic rerun or new cleanup owner.

STATIC_CHECKS.json records source/AST/hash comparisons only. It does not
import or call the target parent, binder, adapter, holder, auditor, trace
parser, sealer or installer. Real Q/CI and diagnostic results must still
come from the original jobs. R24 remains the accepted runtime.

## Preparation revision 03

The earlier revision02 core package remains intact. This revision changes only
the prerequisite module to its independently reviewed revision02 and updates
source metadata. The real D1 preparer preserves git_blob alongside the patch's
path, byte length and SHA256. The new module recomputes that exact Git object
identity and compares all four fields. The old three-field comparison would
reject the real receipt. The parent, sealer, installer, adapter, holder, original
auditor and all monitor/stage/quiet helpers remain byte-identical to revision02.
The original review and its correction addendum are both retained.

The active source-only check program is check_preparation_static_04.py. The
prior package's two checker-only extraction/AST errors are preserved by its
immutable catalog and the attached history; they did not execute a target or
change the runtime protocol. This package's static proof was regenerated for
the new binder identity. Actual campaign input values are still unsealed.
