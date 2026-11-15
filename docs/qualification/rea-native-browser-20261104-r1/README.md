# Native Rust browser capture development evidence

These retained records identify the exact candidates they exercised. They are
not a qualification of a later combined or release binary.

- `native-r1-failed`: the first actual MCP capture failed at its original
  deadline. The original failure receipt and logs are retained unchanged.
- `native-r2-development`: runtime SHA
  `67b0e8292c902ee5202cf8e5dc56fb530306d00bd00a3265a065708083925515`
  passed the ten real MCP capture, refusal, reuse, controller restart, offline
  replay and cancellation checks. Its missing response size metadata was then
  independently found to be inaccurate; this candidate is not the final one.
- `python-reference-r1`: the unchanged Python reference passed the same ten
  real MCP checks. Python remains a development oracle and the existing PDF
  implementation, not a dependency of the native capture subcommand.
- `native-r3-build`: the same native candidate built from stable source hashes
  and passed ten native unit tests, including retained exited-leader custody,
  foreign reaping refusal, descriptor cleanup, directory rename detection and
  create-only publication. Later CDP-settle tests are separately identified.
- `independent`: ten selected phase/path/occurrence body projections matched
  each other and a literal authored byte oracle. The before-fix comparison
  deliberately returned exit 1 / qualified=false for the two unknown-body
  `size:0` findings. Harness HTML, random origins and raw HAR bytes are not
  asserted equal.
- `deadline-development-r1`: the one-second manifest deadline produced a real
  failed original job, with private Chrome/group/profile cleanup, no HAR or
  success receipt, and same-key reuse without relaunch. The deadline occurred
  while awaiting Page.enable; this does not prove resource fetching had begun.
- `python-unit-r1`: 22 retained-reference tests and 17 ledger integrity tests.

The native producer is fixed local-resource HTTP observation. It does not
execute input application scripts, replay browser state, establish host-wide
network isolation or cover descendants that change their process session.
Detected ancestor/output path identity changes refuse publication; hostile
concurrent mutation by the same UID is not a confinement guarantee.

The integration verification must bind the final source manifest and actual
combined/release runtime SHA, repeat real browser capture and deadline tests,
and pass the independent differential after the unknown-size correction.
