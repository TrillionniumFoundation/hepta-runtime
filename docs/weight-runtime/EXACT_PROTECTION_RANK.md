# Exact finite-feature protection rank

`weight_exact_rank` is a pure, bounded Rust computation over explicit F32 bytes.
It reads no file, does no neural forward, fits no model, and changes no weight.
The caller supplies matrix dimensions, little-endian IEEE binary32 hex and the
expected raw-byte SHA256. An optional source declaration is returned as a caller
declaration; the byte proof does not authenticate its semantic provenance.

The accepted profile is 1–128 rows and 1–32 columns. NaNs, infinities, malformed
hex, wrong lengths, mismatched hashes, duplicate request fields and unknown
fields (including supplied certificates) are rejected. Signed zero is retained
in the input hash and interpreted as exact zero for algebra. Subnormals are
decoded directly from their bits without floating-point arithmetic.

Every finite F32 coefficient is an exact dyadic rational. The module clears all
denominators using one exact power of two. Deterministic elimination modulo the
fixed Mersenne prime 2305843009213693951 identifies a candidate full-column minor.
It computes that minor's integer determinant with BigInt fraction-free Bareiss
elimination, checks each division exactly, and independently verifies the
determinant's modular residue. Only a nonzero, agreeing determinant yields
`EXACT_FULL_COLUMN_RANK`. The response contains the original row and column
indices, common power-of-two exponent, exact determinant, residue and byte hash.

A smaller modular rank returns `UNKNOWN`. It does not establish deficient exact
rank, existence of a useful nullspace or permission to issue a nonzero edit.
No numerical rank threshold is used or adjusted. The original numerical solver
may still return `UNKNOWN`; these are separate contracts.

For a verified full-column-rank protection matrix, `C * delta = 0` implies
`delta = 0` in the specified real-linear frozen-feature coordinates. A planner
can stop nonzero strict-protection searches in those coordinates. The caller
must still bind the coordinate, bias/common-row policy and actual feature
producer through its model profile. The proof does not rule out changes hidden
by F32 output-rounding plateaus, approximate protection, changes to upstream
features, unseen inputs or nonlinear rollout effects.

One work counter and one deadline cover byte admission, integer conversion,
modular selection and both determinant calculations. The defaults cap scalar
work at 1,000,000 charged units and wall time at five seconds. A planner may
provide an earlier enclosing deadline. Integer bit length is separately bounded.
Failed admission, time/work exhaustion or disagreeing proofs returns an error
without a partial proof.

Integration is separate: export the module from the Runtime MCP module and call
`evaluate` from the isolated research driver, or pass an existing planner
deadline to `evaluate_with_deadline`. This implementation adds no MCP operation
or artifact publication policy by itself. It uses existing `num-bigint` and
`sha2` dependencies and the Runtime's existing hexadecimal encoder.
