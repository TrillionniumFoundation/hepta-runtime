# Private activity and hot-cache owners

This package preserves three frozen native owners and qualifies their actual
calling boundaries. It does not activate a production MCP route. All **125
original production handlers remain `not_ported`**; `whole_runtime_replaced`,
`production_activated`, and old-stack removal remain false.

## Implemented boundary

| Owner | Actual native boundary | Independent reference domain | Remaining integration |
|---|---|---|---|
| `request_audit_active` | Four real native worker threads share the private activity and read-pin registry, retain and retire opaque lease handles, and join on EOF. | 36 Rust processes; 3,137 commands per side, including 3,113 exact tagged frames and 24 commuting operations compared by phase multiset. | The real server must own the registry and supply its lifetime events. The private transport gate does not qualify arbitrary original interleavings or separate-mutex timing. |
| `request_audit_active_publication` | The same carrier preserves all 21 original base HIA functions and adds detached strong-marker creation followed by later weak-registry publication. | 68 Rust processes; 4,688 commands per side, including 4,656 exact tagged frames and 32 commuting operations. | Batch preparation, final publication, cancellation and completion must call this owner at their original lifecycle points. |
| `request_audit_hot_cache` | Persistent sixteen-entry cache policy executes in HIA, including full stamp matching, insertion order, retry and completion-update decisions. | 194 Rust processes; 855 commands and 6,000 ordered child effects per side. | All four storage child kinds are still scripted. Actual namespace/Archive/hot-directory calls and the process-wide caller are not connected here. |

The two activity executables are fixed, syscall-only carriers. Each embeds its
independently compiled owner image. The hot-cache owner is a borrowed-buffer
image and has no qualified standalone executable. Python is a build and test
driver; Rust executes only as an independent reference.

## Required production wiring

The existing public dispatcher must continue through the shared request
admission, audit and result-storage layer. An ordinary tool argument cannot
select an owner, supply an activity lease, replace configuration, or construct a
trusted directory or Archive token.

For activity, the enclosing native lifecycle owner must allocate and retain the
strong marker, publish its weak binding at the original point, preserve every
read-pin borrow, and retire each lease on its actual completion or drop. The
deferred-publication owner closes a different lifecycle boundary from immediate
create-and-bind; they are not interchangeable.

For hot-cache composition, fixed child kind 100 must call the actual stamp
owner; 101 must call the actual bounded hot-directory enumeration; 102 must
perform the actual Archive existence query; and 103 must perform the actual
Archive append. All replies must retain their original ordering, errors and
opaque capability custody. Scripted child replies from this qualification must
never enter a production graph. The separately qualified store lock still needs
to surround the actual caller operations at the original boundaries.

Native language unwind, arbitrary concurrent cache interleavings, the complete
Archive owner, shared public audit/result admission, and full runtime shutdown
remain separate dependencies. A private callable or leaf passing its reference
domain is not counted as a migrated production handler.

## Reproducible qualification

`build_audit_activity.py` compiles four HIA images with the unchanged pinned d3
compiler, verifies every imported function body and relocation, executes the
native packer twice, and verifies the complete bytes of both emitted ELF files.
No global loader, compiler, buffer profile, or frozen HIA source is changed.

`run_activity_native.py` runs six actual processes: the three semantic suites
and their three borrowed-buffer control suites. It retains complete input and
output frames, actual process receipts and original scope flags. Evidence
admission replays the frozen scenario driver against retained frames without
executing an image, validates response tags and each complete input, and checks
the declared commuting phase multisets.

`compare_activity_original.py` has three independent recipes. Every recipe
builds its exact original Rust project on the qualification machine, checks the
actual Rust 1.95 executable, verifies every locked crate archive and full source
inventory before and after compilation, and executes its complete paired
domain. These recipes deliberately execute the small native domains again and
record those calls separately. They do not relabel retained native output as a
new execution. All reference subprocesses inherit the outer owned process
group. The unchanged outer 180-second deadline and three-second cleanup remain
mandatory; standalone invocations do not establish parent-death cleanup.

Historical frozen observations, current native execution, fresh Rust execution,
and read-only evidence admission are separate records. An evidence inspector
adds zero semantic executions. The immutable source and exact live CI receipts
must be rechecked at aggregate admission before a publication is called fully
qualified.
