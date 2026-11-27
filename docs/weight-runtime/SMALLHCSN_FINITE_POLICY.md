# Fixed SmallHCSN finite policy and complete attempt reservation

## What this adds

`rea_model_session_weight` accepts `smallhcsn_plan` under the same fixed sender40 profile and server-issued session authority. It admits the actual parent, recompiles the supplied native proposal from actual normalized raw inputs, and binds one concrete complete candidate to the original full-model evaluator and budget. There is no caller path, executable, permission token, new model pointer or new journal.

The generic solver remains the existing `qualification/weight_program_runtime_20261122/src/planner.rs`. Its only source change is a parent-module digest import; the qualification crate and native adapter supply the same SHA256. Its solve body, validation, public qualification API and tie behavior are unchanged. Native execution uses a restricted topology:

| State/action | Next state | Compute/result-slot reservation |
|---|---|---|
| Unmodified / STOP | No effect | None |
| Unmodified / source-bound analytic edit | Unverified candidate | Parent: 1 / 1 |
| Unverified candidate / mandatory verify | Verified pass or nonqualification | Candidate plus restored: 2 / 2 |
| Verified terminal | Return research evidence; candidate already reversed | No additional action |

Caller probabilities, utility costs and gain-if-verified are conditional assumptions. A calibration SHA is a commitment to a declaration, not proof of calibration. Existing F64 summation, probability tolerance 1e-12 and incumbent tie tolerance 1e-12 remain observable. A positive gain below the tie threshold can retain STOP. The returned policy is not exact-real, continuous-weight or unknown-environment global optimality.

## Source mapping and requests

Compile and prepare the native proposal first. Native preparation returns `ndu_execution_binding`, containing parent, profile, raw input, complete compiled plan, complete candidate, native proposal program, evaluator, original attempt budget and quality-contract hashes. To inspect a policy, keep that same request and add `ndu` with a `law`, protocol `budget`, and the returned binding as `expected_execution`. The latter is an equality pin, never authority.

`smallhcsn_plan` returns a read-only preparation and policy, including STOP. `smallhcsn_prepare` and `smallhcsn_roundtrip` recompute any supplied policy and reject STOP before an effect intent or forward. They require both the analytic choice and its mandatory verify continuation. The exact original journal ID includes the optional policy request. A client cannot remove the policy and reuse that ID. Request/law/proposal determine the ID first; the native final receipt adds that ID afterwards, without a self-referential hash.

Each native proposal-bearing call performs one pure compile. Each policy-bearing preparation/roundtrip performs one finite solve as well. Both report counts and elapsed wall time. A compile → unplanned preparation → policy inspection → policy roundtrip sequence performs four pure compiles and two finite solves. A further confirmation preparation adds another of each. All source admission, compilation and planning in a roundtrip consume its existing shared sixty-second attempt; no extra model budget is granted.

Before entering the existing solve, checked arithmetic admits at most 1,048,576 weighted successor terms and 65,536 memory cells. The work bound is `(compute+1)*(feedback+1)*sum(outcomes per action)`; memory cells are `(compute+1)*(feedback+1)*states`. The actual closed four-state topology is smaller. The generic solver's original broader API is not changed.

## Reservations, observations and recovery

Protocol compute units represent an existing twenty-second phase reservation under the shared sixty-second model window. Result slots represent those phase outcomes, not human feedback or calibrated costs. All 3 / 3 are reserved by the immutable original intent before any model execution. A crash, parent failure or cancellation does not refund them or authorize another attempt. Existing actual phase charges and completed-result counts stay separate, so an interrupted attempt can show three upfront units, two charged phases and zero completed evaluations.

The inverse and owner I/O remain mandatory even after the model window; this policy does not claim their wall cost is zero or that they can be abandoned at a compute deadline. The original effect permit and retained owner continue through compensation.

New intents persist Linux boot identity and CLOCK_BOOTTIME. Recovery requires the same boot and less than the original sixty seconds before any uncharged model phase. Wall-clock rollback cannot enlarge that window. An old intent without this clock, a reboot, expired counter or clock failure allows the exact saved inverse but no new model evaluation. Recovery never reruns a saved proposal or finite solver. Saved original implementation hashes remain the identity for that old intent.

A zero MSE threshold may pass an unchanged model as an engineering check. Receipts give observed MSE gain, delta correct and strict-improvement status separately. Even a completed fixed quality gate does not verify the law's declared future utility, probability or expected gain. No candidate becomes active through this interface.

## Qualification controls

This layer authors fourteen new controls: six pure finite-policy controls (mandatory verify, near-tie STOP, every action-mapping pin, work and overflow admission, source/law identity, invalid cost/probability/deadline); two deterministic boot-clock controls; three actual original-inverse controls with injected expired/different/missing boot clocks; two source-bound policy/intent controls; and one no-op/observed-gain control. The actual MCP effect-fence control now covers all five fixed-profile operations. These controls are not passes until run.

Meaningful targeted native coverage is `cargo +1.95.0 nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast -E 'test(smallhcsn)'`, repeated under `--no-default-features`, plus the unchanged qualification-crate gate for the shared planner. Normal full check, Clippy, nextest, format, source mapping and release gates remain required. The source does not expand any real-checkpoint, full-model or transport experiment budget.
