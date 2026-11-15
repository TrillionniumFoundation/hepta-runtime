# Second full gate: stopped to align the CI permission input

This attempt was deliberately stopped and is not a complete passing qualification.
Its original summary, source inventories, and logs remain unchanged.

- Original pipeline job: `1a1a16da0b2-96a-6f13`.
- Authoritative terminal: `cancelled`, exit `-15`, output complete.
- Formatting and both Clippy configurations passed. The all-feature nextest
  stage was interrupted; the no-default nextest stage did not run.
- Source before/after tree SHA-256 was identical:
  `d7ccbdcb8dd7ccd6252efb990e83c2fdf67ca9d595e493f6e79dd947f5392e5f`.

Read-only observations found that this runner, nextest, and an actual test
process inherited `0077`, while the checked-in CI workflow explicitly launches
nextest with `0022`. The original runner did not record or override this input.
The separately added `umask-observation-supplement.json` preserves the actual
observations and their timing limits; it does not relabel this run as `0022`.

The old PR84 CI failures were then reproduced with one fixed binary and two new
fixtures: default recursive state creation produced `0755` under `0022`, which
the existing request auditor correctly refused. The same request succeeded with
`0700` under `0077`. See the separate
[paired reproduction](../rea-state-root-umask-20261103-r1/README.md).

The subsequent production fix creates missing state directories as `0700` in
the creation syscall and refuses existing unsafe roots without changing them.
The revised qualification runner sets the child launch umask explicitly to
`0022` in `Popen` and records it in every stage receipt. Those are separate
source and execution conditions, not retroactive changes to this attempt.
