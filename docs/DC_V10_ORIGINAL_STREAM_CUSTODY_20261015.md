# V10 facade preservation of original V4 cooperative stream history

Date: 2026-10-15. This is an additive, source-only patch. It does not
restart V4, Desktop Commander, 8791, the Full Operator tunnel or an
application. The original 66 V10 tool descriptions, all original 50 V4
tool definitions and default-off legacy effect owner are unchanged.

## Actual compatibility failure

Live V4 at 127.0.0.1:8790 retained ten separate cooperative
stream_handoffs directories, all original sessions exited with accepted
owner and complete output. Live V10 at 127.0.0.1:8791 returned an
empty stream_handoff_list. A direct V10 connector cutover would silently
make the ten original sessions and raw stdout/stderr history disappear
from ChatGPT, even if the dispatch queue were empty.

## Source fix

The already separate optional dual-controller Python stdio facade now
routes three read-only names: stream_handoff_list, stream_handoff_status,
and stream_handoff_read. Each session ID is a fixed stream- plus
64-hex controller-local identity. The original owner is resolved by
opening the V4 or V10 private state root, stream_handoffs subdirectory,
session directory and original request.json using directory-relative
O_NOFOLLOW descriptors. The request must match the exact session ID,
contain application_identities, be regular, current-UID-owned and
private with a bounded size. Before and after inode/ctime/mtime/size
must agree. Duplicate JSON keys, truncated reads, bad file modes,
symlinks and uncertain or overlapping ownership cause refusal.

The bounded stream list checks every original session and requires
stable registry membership. When only V4 has entries, it returns the
original V4 result, unchanged and with original raw byte cursors.
When only V10 has entries, it returns original V10. When both have
nonempty lists, it REFUSES rather than dropping an entire backend;
future mixed lists need a separate, genuinely lossless union contract.
An unknown session is not guessed to be a V4 identity.

Under the separately opt-in V4-only effect-owner mode, original
stream_handoff_write and stream_handoff_close names additionally need
exact V4 provenance, with no V10 duplicate record. The original V4
handler owns the actual result and deduplication. The default mode
still refuses all state changes. stream_handoff_prepare remains one
of the original V4 effectful names and is not directed to V10 by
this bridge. No live stream write/close or descriptor adoption was
performed for this candidate. On V4 transport failure, an original
read returns unavailable; an original write returns unknown with
automatic_retry false and never replays to V10.

## Evidence and tested limits

Eighteen new synthetic owner/conflict/path tests passed, alongside
sixteen preceding read-custody and eight V4-only effect owner tests.

A native dual-controller stdio facade actually recovered all ten V4
stream sessions, with original full 66-tool catalog and exact native
statuses, and compared 30 V4-vs-facade byte pages and their SHA256.
A follow-up independently paginated the COMPLETE original archive
for each of 20 stdout/stderr streams. Exact coverage:
ten original sessions, twenty complete retained archives, 5814
original bytes and 20 full-archive byte page comparisons, with chunk
SHA256 recalculated; V4 metadata and archive members were not changed.
All tested sessions were already exited, so this does not qualify
simultaneous *live* app stream owner transfer.

In a separate negative where only the original V4 HTTP address was
unreachable, an original stream list returned unavailable rather
than a fabricated empty list. An original write returned unknown,
automatic_retry false, without dispatching to V10. V10-only
host_health remained available. The real V4 was NOT stopped.

Private reproducible evidence and fixture source, NOT checked in:
 /home/qian-qi/hepta-runtime-stream-custody-evidence-r11-20261015/
 - result.json
 - full-archive.json
 - stream-source-unavailable-result.json
 - stream-custody-live-acceptance-source.py

## Remaining product cutover

This patch does not adopt either original Desktop Commander Node-owned
SSH stream descriptor or its unseen output; it also does not migrate
V10-only asynchronous operation/request/search histories, a global
admission owner or actual registered ChatGPT 66-tool app. Production
Full Operator still exposes the installed 50-tool V4 contract until
a genuinely authorized connector Refresh/Review and production
cutover/rollback. No old V4/DC process may be terminated on the
strength of historical read-only archive evidence alone.
full_dc_replacement_qualified=false.
