# Native namespace versions callable

This file supplements the exact HIA policy ABI. This is a new, unqualified
composition until the actual original/native domain and independent readers pass.

## Ownership

One process-lifetime, eight-byte aligned, 4096-byte environment belongs to one
runtime process. Initialization is exclusive and occurs once. The runtime owner
must retain it until process exit; no reset, clone, or global destructor is
provided. Ordinary and content objects occupy environment offsets 256 and 512.
Their 64 protected HIA bytes begin at object offset 64. Their real glibc
pthread_mutex_t occupies 128..167. A content set is a distinct actual 4096-byte
anonymous mapping with the same object header, created by set_allocate.

Each object stores HNVOBJ01, environment pointer, PID, kind and initialized
Boolean at offsets 0,8,16,24,32. Offset40 is actual mutex poison;48 is the native
owned child mapping ledger;56 is the current invocation while locked. Offset176
is the actual atomic number of borrowed calls,184 is transport quarantine,
192 retains a quarantined invocation. Source poison and transport quarantine
are distinct. The caller retains an exclusive final reference for set_dispose.

The environment contains HNVENV01,PID,initialized,NEXT at 0,8,16,24. NEXT starts
at one and is accessed by a real aligned load and strong lock cmpxchg. It is
shared by all sets. HIA selects retry, exhaustion and high-bit ID composition.
There is no native counter reset or source allocation policy.

## Entry points

initialize(environment,capacity,table,observer,user) returns uint32. Its actual
152-byte table consists of the qualified Watcher's eight libc pointers, the
qualified fingerprint's six libc pointers plus reserved zero, then real
pthread_mutex_init/lock/unlock/destroy pointers. The runtime must supply the
actual functions, retain code lifetimes and initialize without concurrent use.

set_allocate(environment) returns the actual page pointer or negative native
allocation/initialization error. It performs only storage/mutex construction.
entry(request,length,response,capacity,object,object_capacity) uses the HIA
HNVSQ001 request and 128-byte HNVSR001 terminal. Output capacity is at least192;
ordinary/content object capacity is at least256; set capacity is at least4096.
The response's untouched tail remains caller-owned. Constructor kind4 publishes
the allocated set; kind0 means the caller must dispose its now-empty object.

A live set is dropped by HIA command5, which completes the actual qualified
child drop, copies its entire terminal/workspace, disposes/unmaps the child, and
commits the empty state. Then set_dispose(object,4096) destroys its real mutex
and releases the actual page. Empty failed-constructor objects may also be
disposed. Environment/global objects cannot be disposed.

All caller request/output ranges are live, disjoint and outside the complete
environment and target object. Actual FDs and shared File pins are trusted
private capabilities and remain borrowed for the call. A set's members carry
the same qualified native shared File reference, not fabricated numeric handles.
The private Watcher pin exports are available at the composed watcher offset
plus its exact qualified pin_adopt5728, pin_clone5936 and pin_release6048 offsets.

Each call receives a fresh native 131072-byte invocation mapping. Concurrent
calls never share its 8192-byte HIA workspace. Nonzero request generation applies
to that invocation, while the child's own generation monotonically advances.
HIA lock ACK copies all64 policy bytes while holding the actual pthread mutex;
unlock commits precisely the HIA state, releases the mutex and then acknowledges.
Fingerprint executes outside the ordinary mutex. Every child ACK contains the
actual128-byte terminal and entire65536-byte workspace, captured before disposal.

## Observation

observer(user,record,128) is optional and its return is ignored. When absent,
all actual native and HIA paths remain the same. It may copy live buffers and
observe actual resources; it cannot mutate them, supply ACKs, reenter this
runtime or fabricate a syscall. TLS errno is preserved around every callback.

HNVOBS01 records contain stage8, phase16, raw return24, actual errno32,
invocation pointer40, object pointer48, generation56, sequence64, pendingop72,
and three pointer/length pairs at80/88,96/104,112/120. Stage1 is HIA before/after;
stage2 actual effect before/after;stage3 qualified Watcher callback;stage4
qualified fingerprint callback;stage5 transport quarantine. Parent records
retain the full invocation, full target object and full environment. Child
records retain the full child context and full original128-byte child descriptor
plus environment; the complete parent invocation remains accessible at40.

Invocation layout: header0..255, observer256..383, child request512..607,
child response640..767,fingerprint request768..831,response896..1023,
full current HIA input2048..67807,output68096..68287,HIA workspace69632..77823.
Input/output/workspace each have16-byte canaries. The observer records every
owner transition and actual effect, including empty/failed children.

## Separate transport failure

Malformed initial requests return0xffffffff; capacity returns0xfffffffe;
invocation allocation failure returns0xfffffff9. Unexpected mechanics or
continuation corruption returns0xfffffffc and quarantines the actual object.
It cannot impersonate an original source error or success. Quarantine preserves
all known owned mappings and the complete invocation, releases an acquired
mutex exactly once, and refuses further entry/disposal; it does not replay a
completed child command or guess whether an unknown operation closed a resource.
The process owner treats quarantine as fatal. Qualified source-business failures
follow the normal HIA path, including actual partial-constructor drop and retry.
