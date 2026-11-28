# Persistent namespace Watcher — qualified private HIA owner

## Scope

This is the source-defined Watcher core in the unchanged target
`src/mcp/runtime/namespace_version.rs` at
`d3d75c30719db966b004756f610007a7c723729e`. The full original module and all
three original test files are retained. The exact 5,917-byte extraction covers
all bounds, Watch, Watcher, serial, changed, drain, version and pin ownership.

This final owner and its native callable passed the frozen complete 58-case,
984-operation comparison with the unchanged original Rust Watcher, including
observer-off execution, actual inotify and metadata effects, shared File pins,
partial failure state, full buffers and disposal. Independent uploaded readback
also rebuilt all 16 physical evidence refusals and both complete-group admissions.
The source and evidence bindings are in `qualification/namespace_watcher/v1/final/HANDOFF.json`.

A private initial frame cannot supply successful kernel results. Native mechanics
invoke this owner for all policy; observers only copy complete buffers. Global
OnceLock/mutex behavior, ContentWatchSet and namespace fallback are separate
compositions. The qualified fingerprint dependency remains separately bound at
`54b30ca1f97978b4c13b022c13d08a469523a801`.

## Entry and ownership

`f0(input, output, workspace) -> u32` uses the existing HIA borrowed-buffer ABI.
Output is at least 128 bytes and the persistent exclusive workspace is at least
65,536 bytes. Entry returns 128 for a complete response or pending effect.
Malformed input/continuation returns 0xffffffff, capacity failure 0xfffffffe;
both must preserve complete input/output/workspace bytes. Input/output/workspace
regions must not overlap. A context cannot be shared between active invocations.
At most one effect is outstanding. A new command requires a strictly increasing
nonzero private generation and a completed prior command.

The original source's partial effects are retained on business errors. For
example, a drain can already have advanced several generations before a later
failure; a version error additionally calls changed(-1,Q_OVERFLOW), and serial
exhaustion there overrides the previous error. ABI rejection is different from
an accepted original business failure.

## Initial frame

HNWQ0001 is exactly 96 bytes, twelve little-endian u64 words:

| Offset | Field |
|---|---|
|0|HNWQ0001|
|8|command|
|16|nonzero generation|
|24|borrowed directory capability for command2, otherwise0|
|32|optional borrowed shared Arc<File> capability for command2, otherwise0|
|40|limit0..258 for command1, otherwise0|
|48|content boolean for command1, otherwise0|
|56|i32 watch descriptor bits in low32 for command5, otherwise0|
|64|u32 event mask for command5, otherwise0|
|72,80,88|zero|

Commands: 1 initializes a new real Watcher; 2 invokes version_with_pin;
3 invokes drain; 4 drops the Watcher; 5 directly invokes the original changed
method for private source-method controls. Command5 is not a public JSON control
or an alternate native kernel reader. Production event processing uses real
command2/3 read effects.

A limit0 private Watcher follows the original behavior: an empty deque has no
front to evict and the new watch is still appended. Ordinary production wrappers
will use limit128 and composite scopes1..258.

## Complete effect response

HNWR0001 is exactly128 bytes:

|Offset|Field|
|---|---|
|0|HNWR0001|
|8|kind0 success /1 original business error /2 pending actual effect|
|16|private generation|
|24|strict effect sequence within this command|
|32|original command|
|40|effect operation, otherwise0|
|48,56,64|effect arguments a,b,c, otherwise0|
|72|error family0 none /1 actual OS errno /2 source literal|
|80|error code|
|88,96|version id and generation, otherwise0|
|104|current watcher serial|
|112|current number of cached watches|
|120|zero|

Success from command2 returns the full actual Watch(id,generation). Other
successful commands return zero version fields. The tuple in104/112 exposes
source state for the private caller/observer and is not public identity input.

|Operation|Actual required boundary|a,b,c|
|---|---|---|
|1|inotify_init1|526336 (NONBLOCK|CLOEXEC),0,0|
|2|read on the actual owned event FD|event capability,16384,0|
|3|actual directory metadata|borrowed directory capability,0,0|
|4|actual pin creation|borrowed directory,optional shared pin,shared boolean|
|5|inotify_add_watch using actual /proc/self/fd/{pin.fd}|event capability,new owned pin,actual mask|
|6|inotify_rm_watch; return ignored by source|event capability,watch descriptor u32,0|
|7|release one actual owned File pin; close only at final native strong reference|owned pin capability,0,0|
|8|close the owned event File; return ignored by source|event capability,0,0|

Ordinary mask16781248 is CREATE|DELETE|MOVED_FROM|MOVED_TO|DELETE_SELF|MOVE_SELF|
ONLYDIR. Content adds MODIFY|CLOSE_WRITE|ATTRIB (14). Deactivation mask58368 is
Q_OVERFLOW|IGNORED|UNMOUNT|DELETE_SELF. Any event consumes a source serial even
if no watch matches it. Overflow marks every cached watch dead.

Effect4's shared branch must increment the real native shared File lifetime; it
must not duplicate an FD. Its nonshared branch performs actual File::try_clone
semantics. Borrowed directory and supplied shared reference remain owned by the
caller. The transport's owned-capability tokens must be distinguishable from
borrowed tokens and event capability. These are trusted private handles, never
raw request pointers or public authentication claims.

## Completion frame

HNWAK001 is a96-byte header plus a complete actual read payload:

generation8, sequence16, effect24, status32 (0 success /1 OS error), errno40,
value48, value2 56, value3 64, payload bytes72, whole frame extent80, zero88.
Error requires errno1..4095, zero values and no payload. Success errno is zero.
Actual ambient errno for ignored successful cleanup remains in native evidence,
not a fabricated error.

Operation1 returns a positive owned event capability. Operation2 returns actual
count and that many bytes; the source callback's private overreported-count
case may return count>16384 with at most16384 captured buffer bytes, causing the
original invalid-read-length error. Operation3 returns dev,ino,mode. Operation4
returns a positive new owned pin capability. Operation5 returns a nonnegative
i32 watch descriptor. Operations6/7/8 return zero values.

All status, extent, reserved, generation, sequence, operation and state fields
are checked before any output/workspace mutation. Native code must verify that
a completion actually belongs to the outstanding effect and its held resources.

## Persistent state and exact original transitions

Header0..511, temporary moved Watch512..575, records1024..17535 (258*64),
raw read buffer32768..49151; all fit the65536-byte workspace. Initialization
zeros the complete workspace. Each new ordinary command resets only its
transient header fields and moves no existing watches until the original
transition does. Only the actual returned read bytes overwrite the raw buffer;
the entire buffer is zeroed at the beginning of each drain.

|Header offset|State|
|---|---|
|0|HNWST001|
|8|live0/1|
|16|current command;0 completed|
|24|last accepted private generation|
|32|effect sequence|
|40,48|continuation phase and outstanding operation|
|56,64,72|limit,content,event capability|
|80,88|serial and record count|
|96,104|borrowed directory and optional shared pin|
|112,120|read attempts and processed events|
|128,136|read cursor and count|
|144,152|saved original error family and code|
|160,168|current directory dev and ino|
|176,184,192|new owned pin,new wd,new id|
|200,208|removed old owned pin and old wd awaiting cleanup|
|216|reserved0|
|224,232|successful version id and generation|
|240,248,256,264,272,280|last actual ACK status,errno,value,value2,value3,payload length|
|288..511|reserved zero|

A Watch record is64 bytes: owned pin,dev,ino,wd,id,generation,dead boolean,zero.
Records retain exact LRU order. A live identity hit moves the same record to the
back without cloning a pin or allocating a serial. A dead hit removes it,
attempts rm_watch, releases its old pin, then starts new-pin creation. Add-watch
failure captures its errno before releasing the new pin. If serial fails after
add_watch succeeds, only the new pin is dropped; no rm_watch is invented.

After successful serial allocation, a full deque evicts its front by rm_watch
then pin release; only then is the new record appended. Drop closes the event
File before releasing cached pins in deque order, matching Rust field order.
Borrowed root and shared references are never closed by Watcher disposal.

A drain permits exactly64 actual read attempts. EINTR consumes an attempt.
EAGAIN succeeds even on the64th attempt. Other errors, zero read, count overflow,
truncated event/header/name and the16384-event bound follow the source's order.
Version on any drain error calls changed(-1,Q_OVERFLOW) before returning.
The final error is epoch exhausted if that additional changed operation fails.

Literal family2 codes: 1 namespace epoch exhausted;2 namespace event stream
closed;3 invalid namespace event read length;4 namespace event drain budget
exhausted;5 truncated namespace event;6 namespace event size overflow;
7 truncated namespace event name;8 namespace descriptor is not a directory.
These are private typed error identities; an exact public error formatter is
not qualified by this source preparation.

## Composition boundary

The qualified native bridge retains actual read syscall buffers, native capability
records, Arc/FD ownership and disposal with both observed and observer-off
execution. Private source-method callback budgets and actual kernel operations
are separately attributed in the retained evidence.

Global ordinary/content mutex poison/init semantics, atomic composite identities,
ContentWatchSet construction/final drain/invalidation and fingerprint fallback
are outside this private Watcher qualification. This contract does not qualify
archive storage, caches, begin/finish or public MCP handlers.
