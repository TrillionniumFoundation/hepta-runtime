# Audit hot-cache policy

The HIA module implements the persistent bounded hot-cache decisions and the
control flow of the original cache methods. It imports the frozen audit
retention projection validator, byte comparison, UTF-8 validator and word
accessors with exact function bodies and relocated call targets.

The qualification executes unchanged original `cache_hot`, `cache_hot_owned`,
`hot_snapshot_cached`, `hot_snapshot_at`, `seed_missing_archive_record` and
`update_cached_completion` methods. Directory stamps, directory enumeration,
archive-directory lookup and archive save are **explicit scripted children**.
This module alone does not provide actual archive or filesystem operations.

## Persistent cache behavior

The cache holds at most 16 snapshots in insertion order. A successful store
removes every prior snapshot with the same device/inode, evicts the oldest
remaining snapshot only if the bound is full, then appends the new snapshot.
A successful lookup does not move an entry. A consuming hit removes its entry
before returning its records. Cache identity compares the complete stamp.

A cold snapshot obtains its first stamp before touching the cache. It then
initializes and checks cache availability, enumerates records, and validates
the stamp after enumeration. At most three enumerations occur. A third
changed stamp returns diagnostic 44. Child failures stop the sequence at the
same point as the original methods.

Only the final stable enumeration is seeded into the archive. Each record
first asks whether an archive directory already exists for its filename.
An existing counterpart is left alone, including a malformed counterpart:
this policy neither reads nor repairs it. A missing counterpart invokes
archive save with `sync_directory=false, prefer_legacy=true`.
A nonconsuming cold result obtains a fresh stamp after all seeding, then
publishes the cache. A consuming cold result leaves the cache unpopulated.
Earlier archive effects are not rolled back after a later failure.

Completion update obtains its new stamp before cache initialization or poison
checking. It finds the first snapshot equal to the complete supplied old
stamp, then replaces only its first record with a matching request ID and
updates that snapshot's stamp. A missing snapshot or missing ID is a no-op.
The operation does not append records or change insertion order.

## Request and response

Requests use `HRACQ001`, followed by seven little-endian u64 words:

| Offset | Meaning |
| --- | --- |
| 8 | Operation |
| 16 | Private directory token |
| 24 | Private archive token, operation 3 only |
| 32 | Consume boolean, operation 3 only |
| 40 | Input record count |
| 48 | Old stamp byte length: 112 for operation 4, otherwise zero |
| 56 | Reserved zero |

The optional old stamp follows the 64-byte header. Records follow as
`[u64 byte length][HRAJJ001 projection]`. Input records are present only for
operation 1, or exactly one for operation 4. Each projection is 256–512
bytes and preserves `None` versus `Some(0)`, the complete u128 timestamp
and all three UTF-8 strings. Each vector contains at most 512 records,
matching the admitted hot-index bound. Input size is at most 1 MiB.

| Operation | Meaning |
| --- | --- |
| 0 | Private cache metadata inspection |
| 1 | Cache a complete supplied record vector |
| 2 | Check whether the complete current stamp is cached |
| 3 | Read or consume a hot snapshot, with cold validation and seeding |
| 4 | Update a cached completion using the supplied old stamp |
| 5 | Private typed cache-poison trigger |

Operations 0 and 5 require zero directory token. Unused fields must be zero.
Tokens are private references in the child contract; they do not accept
caller-selected public paths or establish an operating-system descriptor.

Responses use `HRACR001` and a 64-byte header: diagnostic at 8, raw errno
at 16, NotFound-kind bit at 24, value at 32, returned record count at 40,
cache entry count at 48 and cache-initialized bit at 56. Records follow
using the same length/projection format. Errors return no record vector,
while preserving already completed child effects and cache state.
Operation 2 returns a boolean value; operation 0 reports the poison flag.

Diagnostic 43 means the hot cache is unavailable. Diagnostic 44 means the
namespace kept changing through the third validation. Child diagnostics,
errno and error-kind fields propagate unchanged. Only child diagnostic 23
admits nonzero errno or an error-kind bit.

A borrowed output needs at least 64 bytes. Operation 3 requires 266,304
bytes for its worst-case vector before issuing any child request. Workspace
requires 8 MiB. Raw rejection codes are `0xffffffff` for malformed
requests/receipts, `0xfffffffe` for capacity, and `0xfffffff9` for an
invalid private cache state.

## Complete stamp

`HRAST001` is exactly 112 bytes. Device and inode occupy offsets 8 and 16.
The signed modification time pair occupies offsets 24 and 32; the signed
change time pair occupies 40 and 48. All signed i64 bits are preserved.

Namespace kind 1 at offset 56 denotes `Version::Watch`: the two u64
members are at 64 and 72, and bytes 80–111 must be zero. Kind 2 denotes
`Version::Fingerprint`: both watch words must be zero and bytes 80–111
hold the complete 32-byte digest. No timestamp-only cache shortcut is used.

## Resumable child contract

Pending effects return raw code `0xfffffff0` and a 96-byte `HRACA001`
action at workspace offset 256. The twelve u64 words carry magic, sequence,
kind, flags, argument offset, argument length, reply offset, reply capacity,
acknowledged sequence, returned byte count, transport errno and reserved zero.
The caller writes only the reply and acknowledgement fields.

Arguments occupy offset 8192 and are copied privately for acknowledgement
validation. Replies occupy offset 524288 with capacity 266288. Input bytes,
all three borrowed lengths, the action descriptor, phase/kind relationship,
argument bytes and exact returned reply envelope are checked on resumption.

| Kind | Argument | Successful reply |
| --- | --- | --- |
| 100 | Directory token as u64 | Complete 112-byte stamp |
| 101 | Directory token as u64 | Record count and length/projection vector |
| 102 | Archive token as u64, followed by UTF-8 filename | Boolean existence |
| 103 | Archive token as u64, followed by complete record projection | Unit |

Kind 103 has flags 2, encoding false sync and true legacy preference.
Other kinds have zero flags. The reply is `HRACC001` with a 48-byte
header: diagnostic, errno, NotFound-kind bit, value and reserved zero.
For kind 100, value is 112 and the stamp follows; for kind 101, value is
the record count; other successful replies have no payload.

The sequence is monotonic across cache calls; exhaustion rejects before
issuing an additional effect. Cache metadata starts at workspace offset 384,
with sixteen ordered physical slot indices at 416. Data slots start at
3145728, use stride 270336 and contain a stamp, record count and bounded
record storage. Ownership of the complete state and its custody gate stays
with the parent. It is not an untrusted serialized memory format.

## Qualification limits

The corpus contains 194 persistent scenarios, 855 commands and 6,000
declared child effects. Each original scenario gets a fresh Rust process,
so `OnceLock` initialization and poison state cannot leak across cases.
The reference uses the exact original stamp/record definitions and cache
functions; its cache is the actual standard-library `OnceLock<Mutex<VecDeque>>`.
The native corpus uses one private HIA session per corresponding lifetime.

Private original poisoning uses actual Rust unwinding while holding a guard.
Native poisoning is an explicit typed state operation. Their subsequent
observations are compared; native language unwinding is not qualified.
The 103 additional controls cover malformed inputs, stamps and record vectors,
receipt replay/corruption, cache metadata corruption, and synthetic boundaries.

The storage children remain scripted. Independent cache mutex timing,
arbitrary concurrent interleavings, actual Archive owners, actual namespace
observation, standalone transport, public request dispatch and complete
audit storage remain unqualified. A parent must supply the actual child
owners and the required STORE_LOCK/cache custody before public use.
