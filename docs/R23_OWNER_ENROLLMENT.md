# R23 execution-owner enrollment: read-only preflight

The deploy/effect_owner_enrollment.py script inspects the **running processes**
for hepta-runtime-operator, hepta-runtime-successor-canary, and
hepta-runtime-v11 via their user services and /proc identities. It never
modifies controller state, changes tokens, freezes admission, starts any
business commands, or invokes owner promotion.

## Necessary configuration before a live handoff trial

- The V4 process needs HEPTA_EFFECT_OWNER_FENCE_REQUIRED=1,
  HEPTA_EFFECT_OWNER_SELF=v4 and the shared private fence directory.
- The V11 process needs HEPTA_EFFECT_OWNER_FENCE_REQUIRED=1,
  HEPTA_EFFECT_OWNER_SELF=v11 and that **same** directory, with a distinct
  V11 state root.
- The V10 predecessor needs HEPTA_EFFECT_OWNER_FENCE_REQUIRED=1
  with NO owner/directory pair, causing direct new-effect submission to
  fail closed while established historical reads remain available.
- The owner record must be private, epoch-bound, pinned to actual V4 state.
  Each installed native binary must match an independently reviewed
  release SHA256 provided to the verifier.

Run the checker with its --reviewed-binary-sha256 argument and a new
owner-private --out filename. Without an exact reviewed SHA256, it
deliberately returns HOLD. The exact actual preflight receipt stays in
the host's protected evidence directory; no raw credentials or paths
are included in the emitted report.

Even READY_FOR_FROZEN_PHASE_TEST_ONLY does NOT certify V4-to-V11 promotion:
production cutover still needs complete all-ingress fencing, request drain,
in-flight completion, old key replay binding, last-delta reconciliation,
and rollback. R23 ownerctl intentionally does not expose promotion.

## Actual state observed on 2026-10-17

R22 user services remained active but had no mandatory shared fence
enforcement. The live read-only tool returned HOLD. No live service was
restarted, stopped, or reconfigured in that observation.
