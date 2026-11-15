# Exact certificate and binary64 relaxation

## Submitted system

Let `hᵢ ∈ [-1,1]^49` have final coordinate exactly `+1`. Let `C ∈ R^147`
contain three affine continuation heads. For a submitted target action `a` and
competitor `b`, a row of `A` places `hᵢ` in head `a`, `-hᵢ` in head `b`, and
zeros elsewhere. The weak ordering for `C + δ` is

```text
A(C + δ) ≥ 0,       ||δ||² ≤ ||C||² / 4.
```

The submitted target must be the first legal maximum of the submitted six
teacher scores. This check does not authenticate their producer. The witness
`y` must be elementwise nonnegative. Set `v = Aᵀy` and `d = -vᵀC`. If a feasible
`δ` existed, multiplying the inequalities by `y` would give `vᵀδ ≥ d`, while
Cauchy–Schwarz gives `vᵀδ ≤ R ||v||`. Thus

```text
d > 0  and  d² > R² ||v||²
```

prove infeasibility. Checking the sign before squaring is essential. Equality
does not prove infeasibility. A zero or unsuccessful witness does not prove
feasibility. The proof neither requires nor claims a converged witness search.

## Exact binary64 interpretation

The mathematical inputs are the actual finite binary64 encodings, interpreted
as exact dyadic numbers. They are not assumed equal to a pre-rounding real
model. Every finite binary64 can be represented as a signed integer `X` times
`2^-1074`; normal and subnormal values use the same scale. Negative zero is zero
in the algebra but its bytes remain distinct in content identities.

| Quantity | Integer coefficient | Scale |
|---|---|---|
| `C`, `h`, `y` | decoded binary64 integer | `2^-1074` |
| `v` | sum of signed `Y H` products | `2^-2148` |
| `||C||²` | `Σ C²` | `2^-2148` |
| `d` | `-Σ v C` | `2^-3222` |
| `||v||²` | `Σ v²` | `2^-4296` |
| `R²` | `Σ C²` | `2^-2150` |
| `R² ||v||²` | `(Σ C²)(Σ v²)` | `2^-6446` |

Consequently the ideal comparison is exactly
`d_integer > 0 && 4*d_integer² > center_norm_integer*dual_norm_integer`.
No floating-point dot product, norm, tolerance, square root, or division enters
a verdict. Rust uses the already-locked `num-bigint` version **0.5.1** as a
direct pinned dependency; no package upgrade or new transitive package is
needed.

## Conditional F64 necessary relaxation

The declared execution graph is a 49-term affine dot product using separate
binary64 products and at most 48 binary64 additions, round-to-nearest
ties-to-even, gradual underflow, and no overflow. Hidden coordinates are fixed
at the submitted binary64 values. The bound uses 98 rounding steps
conservatively for that graph, not an arbitrary inferred feature count. It
does not cover a changed hidden representation or unspecified hardware
semantics by declaration alone.

Let `u = 2^-53`, `η = 2^-1074`, and
`γ98 = 98*u/(1-98*u)`. Compute the integer upper bound `Ru = ceil(R)` by integer
Newton iteration plus an exact final test. Since each coefficient displacement
in the ball is at most `R ≤ Ru`, and `|h| ≤ 1`, the headwise absolute error bound
is

```text
E_j = γ98 * (Σ_k |C_jk| + 49 Ru) + 98 η / (1 - 98 u).
```

The additive underflow term is retained. The input is rejected unless

```text
49 * (max_k |C_k| + Ru) < 2^1000,
```

which conservatively keeps every product and partial sum far below overflow
throughout the ball. The tool validates this bound, but does not inspect CPU
rounding mode, contraction, or flush-to-zero settings.

For each comparison, computed F64 target ≥ competitor implies its real affine
difference is at least `-(E_a + E_b)`. Therefore the F64 execution's ordering
requires the relaxed system

```text
Aδ ≥ -AC - ε,       ε_i = E_a + E_b.
```

Set `d_f64 = d - yᵀε`. A strictly positive `d_f64` and
`d_f64² > R² ||v||²` exclude even this necessary relaxation. The response reports
this separately from the ideal-real proof. A tiny subnormal example certifies
the ideal system but fails the relaxed test, demonstrating why both verdicts
matter.

For `D = 2^53 - 98`, the code computes

```text
E_num_j = 98 * (Σ |C_units_j| + 49 Ru * 2^1074 + 2^53)
E_j = E_num_j / (D * 2^1074)
W = Σ_i Y_units_i * (E_num_a + E_num_b)
d_f64_integer = d_integer * D - W * 2^1074.
```

The relaxed comparison is exactly
`d_f64_integer > 0 && 4*d_f64_integer² > center_norm*dual_norm*D²`.
Outputs expose the exact rational values so a different implementation can
recompute every quantity. The Python reference uses `Fraction` directly from
binary64 values and does not reuse these fixed-integer scaling functions.

## What the proof cannot establish

It does not establish task-value optimality, useful-policy impossibility,
hidden-program correctness, teacher correctness, a minimum required radius,
global NDU control, real-market performance, or success of a weight edit. It
applies to the submitted comparisons, fixed representation, fixed center and
fixed radius. The original dual optimization's iteration limit does not weaken
a checked separating witness, but prevents a convergence/optimality claim.
