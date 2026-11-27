# Restore an existing F32 candidate when its original path is unavailable

This increment adds an explicit restore-first operation. It reads the original
durable guard intent, authenticates an already published canonical candidate,
calls the existing inverse owner and verifies the restored artifact through a
fresh source-bound request. It does not open the original model pathname or run
the parent/candidate forward again. It never creates a new candidate or changes
a live pointer.

## The concrete recovery gap

The ordinary source-bound F32 wrapper authenticates bias from the original path
before entering the existing guard journal. The guard journal replays the full
guard before forcing restoration of an interrupted request. If the original
file has disappeared or changed, that replay cannot reach restoration even when
the candidate was already published. The journal's `candidate.json` is written
after the guard returns, so a process can die with a canonical candidate present
but no saved candidate receipt or completion.

The existing source and model store remain unchanged by such a candidate
publication; candidates are separate immutable artifacts. Nevertheless, an
actual restored artifact and its new-request output must be verified before
claiming that recovery completed.

## Existing owners remain authoritative

The guard journal gains a read-only `open_existing` admission. It does not create
a journal root, entry or record. It retains the original directory `flock`, so a
still-running original guard process excludes recovery. The original entry must
be private, owned, singly linked where applicable, match its `wgj1_` SHA identity,
and bind the exact original canonical roots, state and supported guard semantics.
The actual typed `GuardedPatchParams` are read from that intent; the recovery
caller cannot substitute new labels, bias values, features or exact edits.

An opaque handle retains the pinned journal and entry descriptors. Intent,
candidate and completion bytes are rechecked before and after inverse publication
and after the fresh restored request. Recovery writes none of those original
records and does not treat their old acceptance or metrics as current evaluation.
The original named source fingerprint remains explicitly incomplete as an
execution-closure identity. The external research plan binds the actual compiled
executable and the complete recovery request separately.

The existing artifact owner retains the model store, count/byte quotas, private
files, exact inverse bytes, full file hashes, exclusive directory publication and
idempotent restore identities. The original `evaluate`, `apply` and `restore`
function bodies are unchanged. No second model store or replacement lifecycle is
introduced. The research execution evidence directory is a separate experiment
ledger containing intent and attempt receipts, never model ownership state.

## Candidate lookup and restore-first behavior

The request supplies the original journal ID, original complete source SHA,
expected complete candidate SHA, stored-bias binding and an optional known
candidate artifact ID. If the original candidate record exists, its source and
target direction must match. A caller-supplied candidate ID must also agree with
that record. Every actual candidate is authenticated against its canonical
manifest and complete file bytes.

If neither the original record nor the caller provides an ID, the operation
examines at most the existing 128-entry artifact limit. Metadata is checked first;
complete model hashing is needed only for a matching F32 candidate. Exactly one
published `wa1_` artifact must match all of:

- Original source path and complete SHA from the durable request.
- Expected complete candidate SHA.
- Original patch kind, tensor name and F32 dtype.
- Every exact edit index, byte offset, old bytes and replacement bytes, with no
  extra or repeated edits.
- Actual named weight shape, byte extent, stored F32 bias and complete source
  capture identity.

The original exact F32 norm budget is checked again when the original request
specified one. Actual bias is read from the admitted candidate and must equal
the original intent's supplied bias bit for bit. Matching header, tensor and
metadata checks span the same admitted descriptor. A changed source file at the
old pathname has no authority in this path and is not overwritten.

After read-only preflight, the operation directly invokes the original
`restore_with_state(candidate_id)`. It checks receipt direction
candidate-to-original, then reopens the restored artifact by canonical ID using
`source_bound_f32::next_request_with_state`. That request checks the restored
whole-file SHA, actual stored bias and actual native linear output. Only this
restored-head request consumes a forward allowance. There is no parent or
candidate forward replay and no parameter fitting.

An absent journal, a live journal owner, an altered intent, wrong candidate/bias
binding, a tampered artifact, no unique match or an exhausted owner quota fails
closed. A pending stage is not a published candidate: it remains retained owner
evidence and is never promoted or deleted by this operation. If there is no
published candidate, the outcome remains unverified rather than creating one
just to restore it.

## Cancellation, process failure and budgets

Public execution reuses the existing cohort concurrency permit and effect fence
and retains them around the complete operation. The response deadline is 420
seconds, matching the sum of a 60-second read-only preflight, the existing public
restore API's 300-second response allowance and a 60-second fresh restored request.
This new retained path does not impose a separate cancellable 300-second timeout
inside inverse publication; its 420-second limit is a response deadline.
The admitted inverse publication is not cancelled halfway through an atomic
transition. As in the existing retained-owner design, the owner task can finish
after a caller response deadline while the runtime remains alive. A response
timeout is UNKNOWN and must be reconciled using the same operation identity.
This is not a bound on late write completion or a guarantee across runtime exit.

A native process crash releases its OS journal lock. A later explicit recovery
process reacquires that same original intent and authenticates the same published
candidate before invoking the same idempotent inverse. Each later attempt needs
an explicit experiment allowance; it is not a free cache. The normal recovery
allowance is one restored-head forward. Prior interrupted CPU cost remains
unknown unless the actual execution owner measured it. The response does not
claim to have observed the prior process crash or to run a background daemon.

An external one-shot experiment ledger records the exact package/binary/config,
original request and fixed controller job key before launch. Missing stdout first
requires status/output reconciliation of that original job. Restore-first is used
only after the execution owner establishes that the original invocation is no
longer running, or the original journal lock refuses it. Native `flock` remains
the enforcement against a concurrent original guard even if orchestration is
mistaken.

## Isolated driver

The existing explicit-config research example gains this wire operation:

```json
{
  "kind": "f32_recover_original_intent",
  "params": {
    "journal_id": "wgj1_<original-intent-sha256>",
    "original_source_sha256": "<original-complete-sha256>",
    "expected_candidate_sha256": "<sealed-candidate-complete-sha256>",
    "candidate_artifact_id": null,
    "bias_binding": {
      "tensor_name": "body.readout.bias",
      "payload_sha256": "<actual-original-bias-payload-sha256>"
    }
  }
}
```

The configured roots and state must be the original canonical directories.
The original model file may be missing or changed; the directories and original
native owner state still need to be available. The request uses the same
compiled example worker delegation and requires no active-service change.
The separate full SmallHCSN example is untouched.

## Qualification status and controls

Six main Rust controls and one ignored subprocess worker are authored:

- Completed original intent, then a missing or changed original path: actual
  inverse publication and fresh restored output, without modifying old records
  or the missing/changed original path; a repeat uses the same restore identity.
- Wrong original SHA, candidate SHA, bias hash, candidate hint or journal identity
  rejects before any inverse publication.
- Tampered candidate or original intent rejects.
- An absent journal is not created by recovery.
- Actual SIGKILL after intent but before publication remains unverified without
  creating a candidate. Actual SIGKILL after accepted candidate publication but
  before candidate/completion records, followed by source deletion and a fresh
  process, locates and restores the canonical artifact without parent replay.
- A still-live original guard holding the journal lock refuses recovery and
  produces no extra artifact.

At authoring these are **not yet compiled or native-executed**. Local rustfmt 1.96
is only source preparation; qualification requires the unchanged normal Rust
1.95 CI gates for both feature sets. Actual SIGKILL receipt lines from a passing
native test and actual binary/package identities are required before reporting
process-crash recovery as observed. This module reports neither full-model
execution nor task-quality improvement nor production eligibility.
