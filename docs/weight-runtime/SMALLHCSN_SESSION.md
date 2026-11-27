# Session-bound fixed SmallHCSN research

## Status and scope

This source adds a fixed-profile branch to the existing `rea_model_session_weight` MCP route. It is research code, not deployment approval or provider qualification. The model has eight neurons, six ticks, two choices, nine raw features and the existing centered-boundary QVI / mixed value-and-risk equations. Only `body.input_drive.weight[4,9]` and `body.input_drive.bias[4]` may change. All other ten tensor payloads, aliases, header and remaining bytes must remain identical.

The existing F32 readout JSON shape and guard remain intact. The new hidden shape has `session_id`, `parent_sha256`, `profile: "smallhcsn_centered_sender_drive_and_bias40_v1"`, and an operation. It has no `readout`, path, executable, state-root or caller-authority argument. The server resolves the current owner and transfers its one effect admission permit across the existing four-slot capacity and retained cohort task.

## Shared source and semantic evidence

The fixed numerical kernel lives in `weight_smallhcsn`; both original explicit-file examples call it. Matrix and physics arithmetic have not been reimplemented. Hidden candidates reconstruct every tensor from the complete, independently reopened candidate bytes after the existing opaque sender plan verifies the exact changes.

Preparation returns a bounded source-bound semantic map. It lists the actual twelve tensor roles, dtypes, shapes, offsets and payload hashes; the allowed forty sender parameters; and the protected tensors. Recurrent activity is derived from the actual fixed mask and selected first eight columns: the known canonical profile has 48 structurally eligible coordinates and 144 inert coordinates. This is a program dependency statement, not measured causal benefit. Sender mark parameters can affect signed state and diagnostics but have no arithmetic path to completed final scores in this boundary-only / receiver-only branch. Raw boundary parameters are inactive in the fixed QVI branch. The twenty receiver features are continuation value, first-passage risk, signed event rate, event rate and normalized margin, grouped for four receivers. The raw two-output head is not labeled Call/Put, Belief, learned Continuation Q or a global NDU controller.

## Operations

| Operation | Inputs | Effect |
|---|---|---|
| `smallhcsn_prepare` | Fixed profile JSON, original HCSNIN1 raw bytes as lowercase hex, exact forty-coordinate-scope plan and minimum MSE gain | Authenticates the session and actual source, checks exact represented-F32 radii, returns original request and artifact identities plus semantic evidence. Zero model forwards; no artifact or guard/cohort-journal publication. |
| `smallhcsn_roundtrip` | Identical request and prepared original journal ID | Parent full-model evaluation; canonical two-tensor publication; actual candidate reopen and six-tick evaluation; canonical inverse; independent restored-byte reopen and, when still allowed, fresh full-model evaluation. |
| `smallhcsn_recover` | Original journal ID and expected candidate SHA-256 only | Loads the same durable bound intent. It never substitutes new inputs, profile or plan, never opens the old workspace source and never replays a charged model phase. It can perform the exact inverse without a forward. |

The input profile is at most 49,152 UTF-8 bytes and contains exactly one canonical parent. The raw input is at most 65,536 decoded bytes and 80 queries; its original normalizers, external baseline values and labels remain hash bound. The model artifact is at most 131,072 bytes. Requests stay under 1 MiB and final wire responses under 60 KiB.

The parent model and candidate use the same actual raw batch and exact original F32 arithmetic order. Candidate qualification requires a finite full-model result, original physical diagnostics within 2e-9, at least the declared MSE reduction and no decrease in correctly classified queries. Every candidate is reversed, including one that passes. A fresh restored output must exactly match the parent's output bytes for a successful complete roundtrip. A zero minimum gain can admit a no-op as an engineering check. Receipts separately report observed MSE gain, delta correct and strict improvement; successful transactions do not establish caller-declared NDU utility. Labels, target provenance and NDU optimality remain unverified declarations.

## Durable budgets and failures

The same original cohort intent retains the authority binding, parent/profile/raw/plan/candidate/source identities, evaluator source hash, budget and original native clock window. Its three fixed model phases each reserve twenty seconds in a create-only, fsynced record before execution. A charged phase cannot be replayed even if a crash loses its result. Reservations are never refunded.

Normal processing has a single sixty-second model-attempt window. New intents persist Linux boot identity and the kernel CLOCK_BOOTTIME counter as well as original wall-clock start/end. Every new phase requires the same boot and less than sixty seconds of elapsed boottime; the wall and local Instant deadlines can only shorten that allowance. Wall time rolling back inside its former interval cannot reopen model work after boottime expiry. A missing legacy boot stamp, reboot, backwards observed counter, malformed current clock sample or failed current clock read permits exact inverse only. A malformed stamp inside the persisted original intent fails integrity validation and does not authorize inverse publication. The three phase reservations remain a separate cross-process cap. Kernel checks are cooperative, so the final bounded numerical unit may finish after a check; this is not an OS hard-real-time or external clock-attestation claim.

The original 420-second RPC cutoff includes effect admission and capacity waiting. Cancellation after admission does not cancel the retained inverse task. The original artifact-store lock is reused, including its ten-second busy limit; no new mutex or replay store is introduced. Store readback and compensation remain allowed after the model window expires. Byte restoration, completed model evaluation and quality qualification are separate receipt fields.

If a response or process disappears after publication, explicit recovery reopens the exact original candidate/inverse and its saved intent. A previously published inverse can be verified even when the candidate or workspace source has disappeared. Missing original intent, altered authority, inconsistent saved input, wrong candidate commitment or a missing completed candidate fails closed; the route does not create a replacement plan. Existing bound journals cannot be relaunched with a fresh time window. A failed inverse remains unresolved for explicit same-ID recovery; there is no background retry.

## Compatibility and upgrade behavior

New optional fields are omitted for legacy unbound cohort manifests and intents. Existing F32 session structures and their JSON representation are preserved. Legacy unbound cohort restoration refuses the new session-bound artifacts; omitting a binding cannot bypass the fixed authority.

Source changes legitimately change newly prepared identities. Historical fixed-profile recovery uses the implementation recorded in the original intent to check that old request, rather than pretending a new-source replay has the old identity. The current authenticated owner and exact runtime policy still have to match. If the current evaluator source differs, the exact inverse is allowed but a new model evaluation is refused. The saved roots use their original spellings, so changed configuration spellings fail closed.

## Validation boundary

Meaningful synthetic controls cover zero-forward preparation, closed legacy/new wire shapes, a complete six-tick no-op roundtrip, rejected quality with inverse, other-owner and legacy restore refusal, caller cancellation plus post-publication revocation, source-missing recovery with unknown charges, spent/expired/backward-clock budgets, changed saved input and the actual MCP effect fence. These controls must run through the pinned Rust 1.95 CI before any native qualification is claimed. Pure semantic controls exercise actual byte hashes and structural mask changes without running a model.

Existing real-model, public transport and experiment budgets are not expanded by this implementation. The explicit-file CLI, in-process synthetic controls, same-credential black-box transport and real SmallHCSN parity are distinct qualification layers. No file here proves the latter layers have passed.

The optional native shared compiler and fixed conditional policy are documented in `SMALLHCSN_NATIVE_COMPILE.md` and `SMALLHCSN_FINITE_POLICY.md`. A policy-selected attempt reserves all three phase/result units upfront in its original intent; early failure does not refund that reservation. Actual phase charges and completed evaluations remain separate.
