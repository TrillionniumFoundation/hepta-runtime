# A48 follow-up: failed resource and correctness gates

The complete A48 large ABBA is final and failed adoption. All 80 measurements
were attempted once. The candidate had 30/32 correct C4 replies, and the
conservative C1 CPU-per-attempt ratio (1.882656) and C4 inclusive
CPU-per-attempt ratio (1.473166) both exceeded the unchanged 1.10 limits.
The qualified source and the passed small comparison do not override these
failures. All four controller outcomes and both candidate deadline errors remain
in the original report. See [large-results.md](large-results.md).

## Measured reason to continue

The candidate controllers recorded 995,383 and 939,922 whole-life voluntary
context switches, compared with 5,151 and 4,648 for r07. These counters cover
setup, measurement and shutdown; they do not identify the cause of an individual
query. The source performs one command/result channel exchange for each original
record across two reader lanes. Reducing this exchange frequency is a concrete
hypothesis supported by the measured CPU regression and source inspection,
not an established performance result.

A separately identified A49 diagnostic uses the exact qualified A48 release
with the existing `HEPTA_ARCHIVE_INDEX_TRACE=1` switch. It admits one fresh
candidate controller with four C1 calls and four C4 waves (16 C4 calls), the
same 65,536-record fixture and original deadlines. The original full validation,
DTO oracle, file/source/ELF fences and raw child cleanup are retained. It uses
new output and fixture paths, performs no retry, and cannot replace, repair or
be pooled into A48's comparison.

Existing SteadyTrace distinguishes store-lock wait and snapshot-read time.
It emits only stages longer than 100 ms and has no request or cohort ID.
The diagnostic must retain all stderr and its limitations: an absent trace
is not proof of absent work, and pending client IDs or trace counts do not
establish shared server-cohort membership.

## Conditional implementation boundary

A small fixed batch per reader lane is being considered to amortize channel
handoffs. It must preserve two readers, a stated finite record bound including
any coordinator buffer, complete fresh Record/stamp validation, per-record
cancellation/deadline checks, unambiguous result counts/identities, and actual
joins on error, deadline, partial spawn and panic. It must preserve the global
store/state guards, off-page checks and final namespace fences. An additional
candidate needs its own complete qualification and the same small/large gates.
No result for that candidate is claimed in this A48 checkpoint.

The 1 ms collection cutoff and 3 s metadata deadline stay fixed. No original
read may be skipped and no historical successful content observation becomes
a lease. The current evidence does not establish a hardware ceiling, justify
more reader threads, or prove optimization exhaustion.

## Separate authentication boundary

Current native multi-host admission remains blocked by the current-agent
precondition: the socket exists, but the retained `ssh-add -l` call returned
1 and did not establish a usable identity or an exact current identity count.
The normal next step is to restore the already-authorized current agent, bind
the existing profile to the current socket and pinned SSH configuration/known
hosts, then execute the original bounded multi-host validation. Local archive
changes do not remove this dependency or supply multi-host acceptance.
