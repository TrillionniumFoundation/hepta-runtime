"""Compare the compiled planner with exact dyadic-score grid and rational DP.

The grid covers all policy cells for these fixtures without deriving thresholds.
This is a supplied-law scalar-switch check, not a serialized model forward test.
"""
from fractions import Fraction as F
import json
import math
import random
import subprocess
import sys

rng = random.Random(20261124)
cases = 256
misses = 0
strict_improvements = 0
for case in range(cases):
    count = 6
    scores = [[F(rng.randrange(-4, 5), 8) for _ in range(6)] for _ in range(count)]
    rewards = [[F(rng.randrange(-8, 9), 8) for _ in range(3)] for _ in range(count)]
    fees = [[F(rng.randrange(1, 5), 16) for _ in range(3)] for _ in range(count)]
    masks = [rng.randrange(1, 64) for _ in range(count - 1)] + [49]

    def actions(shift):
        return [max((a for a in range(6) if mask & (1 << a)),
                    key=lambda a: (row[a] + (shift if a in (1, 2, 3) else 0), -a))
                for mask, row in zip(masks, scores)]

    def value(policy, factor):
        result = F(0)
        for i in range(count - 1, -1, -1):
            a = policy[i]
            result = (result - factor * fees[i][a - 1] if a in (1, 2, 3)
                      else rewards[i][(0, 4, 5).index(a)])
        return result

    incumbent = actions(F(0))
    baseline = [value(incumbent, f) for f in (1, 2)]
    oracle = max(min(value(actions(F(k, 16)), f) - b for f, b in zip((1, 2), baseline))
                 for k in range(-8, 9))
    rows = [f'HEPTA_DAG_V1 {count} 0']
    for i in range(count):
        row = [i, masks[i], *[float(x) for x in rewards[i]], *([incumbent[i]] * 3)]
        for a in (1, 2, 3):
            row.extend([1, 1, i + 1, float(fees[i][a - 1])]
                       if masks[i] & (1 << a) else [0])
        rows.append(' '.join(map(str, row)))
    rows.append('HEPTA_Q_SCORES_V1')
    rows.extend(' '.join(str(float(x)) for x in row) for row in scores)
    run = subprocess.run([*sys.argv[1:], '--plan-q-bias', '1', '2', '.5'],
                         input='\n'.join(rows), capture_output=True, text=True, check=True)
    name, shift, low, high, _, codes = run.stdout.split()
    selected = [int(x) for x in codes]
    realized = [value(selected, f) - b for f, b in zip((1, 2), baseline)]
    assert name == 'Q_BIAS_PLAN' and abs(float(shift)) <= .5
    assert selected == actions(F(float(shift)))
    assert all(math.isclose(float(g), float(v), abs_tol=1e-12)
               for g, v in zip((low, high), realized)), (case, run.stdout)
    strict_improvements += oracle > 0
    if not math.isclose(float(min(realized)), float(oracle), abs_tol=1e-12):
        misses += 1
    if oracle <= 0:
        assert float(shift) == 0 and selected == incumbent

print(json.dumps({'seed': 20261124, 'cases': cases, 'strict_improvement_cases': strict_improvements,
                  'missed_optimal_values': misses, 'oracle': 'exact_rational_dyadic_grid'}))
assert misses == 0, f'{misses} closed-interval policy optima were missed'
