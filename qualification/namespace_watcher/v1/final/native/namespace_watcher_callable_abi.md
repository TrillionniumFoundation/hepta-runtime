# Persistent namespace Watcher — qualified native callable

This final source composes the qualified fixed-eight HIA Watcher with actual
Linux inotify calls and native shared File references. The complete frozen
58-case, 984-operation domain passed unchanged-original, observed and observer-off
comparison, physical evidence controls and independent uploaded readback.
The exact image and source bindings are in `qualification/namespace_watcher/v1/final/HANDOFF.json`.

The global OnceLock/mutex wrappers, ContentWatchSet, namespace fallback, cache,
archive storage and public handlers are separate compositions. Build qualification
executes only compilers and the HIA packer; runtime evidence is attributed to
its separate completed actual capture.

## Exports

All exports follow Linux x86-64 System V. Flat offsets are read from the actual
zero-relocation assembler symbol table and frozen with the complete packed image.
The entry's sixth argument is context capacity, not a request-controlled address.

| Export | Arguments | Result |
|---|---|---|
| namespace_watcher_initialize | context, capacity, eight-pointer libc table, observer or0, observer user | 0 or private rejection |
| namespace_watcher_bind | context, capacity, borrowed directory FD or-1, borrowed shared pin or0 | 0 or private rejection |
| namespace_watcher_entry | request, request bytes96, output, output capacity, context, context capacity | 128 complete HNWR0001, or private rejection |
| namespace_watcher_dispose | context, capacity | 0 only after real command4 disposed all owned resources |
| namespace_file_pin_adopt | owned FD, actual close function, actual errno-location function | native opaque pointer, or negative errno with FD still caller-owned |
| namespace_file_pin_clone | actual live pin held by a real caller reference | same opaque pointer after actual atomic increment, or-22 |
| namespace_file_pin_release | one owned pin, disjoint output64 | 0 after actual decrement; last reference actually closes and unmaps |

The context is131072 bytes, aligned8, exclusively borrowed across each call.
The three entry regions must be disjoint; malformed/capacity rejections preserve
their complete physical bytes. Context initialization cannot overwrite a live
HNWCTX01 context. Bind does not clone or consume the caller's reference.
A supplied pin must name the same actual FD as the borrowed directory and the
same actual libc close/errno functions as this context. Passing a stale or
invented pointer is outside this trusted private capability ABI.

The eight-pointer table is, in order: inotify_init1,read,fstat,fcntl,
inotify_add_watch,inotify_rm_watch,close,__errno_location. These are actual native
functions. Neither JSON nor the HIA request can provide their results.
Metadata uses actual x86-64 libc fstat layout; original File::metadata may use a
different kernel entry. Captures must retain the actual syscall names and complete
physical buffers, then compare source-level dev/ino/mode honestly.

Request command2 uses root capability1 and optional shared capability3; all other
request framing is the frozen HIA ABI. The actual owned event capability is2.
Owned File pins are separate native page addresses. Each context tracks its own
owned pins independently of HIA workspace, so unexpected transport failure can
close actual resources without trusting modified HIA records.

The HIA owns all drain bounds, serial allocation, record/LRU order, source error
selection, real watch masks, and cleanup ordering. Native code performs each
requested boundary once and returns its exact outcome. It does not synthesize
events, retry reads, shortcut metadata, decide eviction, or compute namespace
versions. Errors after accepted original transitions retain partial changes.

## Actual File reference lifetime

Each pin is a4096-byte anonymous native page: HNWFP001, atomic strong count,
owned FD, size4096, actual close pointer, actual errno pointer; remaining bytes0.
Clone and release perform real locked compare-and-exchange on that count.
The caller must hold a reference during clone. Last release calls close exactly
once, captures its actual errno immediately, then munmaps the page. A failed close
is not retried and is not silently recategorized as successful kernel cleanup.
The source ignores File-drop errors; the complete native result remains evidence.
Extreme Arc-overflow abort behavior is not claimed by this private bounded ABI.

Release output HNWFPR01 is64 bytes: magic,old count,new count,actual FD,
actual close return,actual errno,actual munmap return,zero. For nonlast release,
close return and munmap return are0 and errno is unchanged ambient errno; old
count>1 unambiguously records that no close happened. Failed private admission
does not decrement references or write this output.

## Context and observations

| Offset | Content |
|---|---|
|0..159|native framing/lifecycle/last generation/borrowed root and shared pin/observer/TLS/actual resources/counters|
|160..255|reserved0|
|256..319|actual eight-function libc table|
|512..4655|up to259 native owned pin/actual watch-descriptor pairs|
|6144..6287|complete actual fstat buffer144|
|6400..6463|actual /proc/self/fd decimal path64|
|6528..6591|complete native File release record64|
|8192..24671|actual HIA initial/ACK input, up to16480 bytes, plus16-byte guard|
|24704..24847|HIA output128 plus16-byte guard|
|24960..25087|complete observation descriptor128|
|32768..98319|exclusive HIA workspace65536 plus16-byte guard|
|98336..114719|actual persistent inotify read buffer16384; zeroed once at the start of each drain|

The optional observer is called with (user,context,131072,descriptor,128).
It only copies owned complete buffers; its return is ignored. Caller errno is
restored around observation, so the observer cannot choose kernel results.
Observed and observer-off native domains must both be executed later.

HNWOWN01 records before/after the actual HIA invocation: stage8,return16,
generation24,command32,effect sequence40,input ptr48/length56,
output ptr64/length72,workspace ptr80/length88,owner calls96,
boundary calls104,event FD112,pin count120.

HNWBN001 records before/after an actual requested boundary: stage8,return16,
generation24,command32,operation40,sequence48,HIA arguments56/64/72,
event FD80,borrowed root FD88,actual return96,actual errno104,pin count112,
boundary calls120. Full context includes all actual read/stat/path/release bytes.
Pin pages are separately copied while live; no reader may dereference a
released page. Kernel trace and release record retain actual disposal custody.

HNWNCL01 is exceptional native transport cleanup, not an original HIA effect.
Transport failures return0xfffffffc and poison the context; busy returns
0xfffffffb, malformed0xffffffff, capacity0xfffffffe. Unexpected cleanup is
separate from original business kind1. No poisoned result counts as semantic
PASS. The standard success result is only copied to the external output after
complete HIA/native resource and frame validation.

## Production installation boundary

The final INSTALL manifest contains only this semantic owner, native callable
source, fixed HIA packer and ABI documentation. Original source, fixtures,
readers, process streams and failed attempts remain qualification evidence.
The five executable/source-composition files are byte-identical to the qualified
fixed-eight build; documentation records the completed qualification.

The native boundary separates the actual kernel read buffer from the framed HIA
ACK and its canary. The kernel buffer starts fully zeroed once per command2/3,
matching the original local read buffer. Each successful read copies exactly
its returned bytes into the ACK; later HIA guard writes cannot alter the
actual kernel buffer tail before the next read. All bytes remain in the
complete observed context. The HIA owner and effect/ACK ABI do not change.
