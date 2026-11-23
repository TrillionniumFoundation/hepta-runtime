"""Exercise the published command lines against a two-state, one-branch graph."""
import math
import subprocess
import sys


def invoke(*args, fee=0.1):
    graph = (f"HEPTA_DAG_V1 2 0\n0 3 0 0 0 0 1 0 1 1 1 {fee} 0 0\n"
             "1 16 0 .8 0 4 4 4 0 0 0\n")
    return subprocess.run([*sys.argv[1:], *args], input=graph, text=True, capture_output=True)


def read(*args, fee=0.1):
    run = invoke(*args, fee=fee)
    run.check_returncode()
    rows = [line.split() for line in run.stdout.splitlines()]
    return {name: ([float(x) for x in values], policy) for name, *values, policy in rows}


def check(row, values, policy):
    actual, actions = row
    assert len(actual) == len(values) and actions == policy, row
    assert all(math.isclose(a, b, abs_tol=1e-12) for a, b in zip(actual, values)), row


fees = read("--fee-band", "1", "2")
assert set(fees) == {"BAND_ONE_DIRECT", "BAND_BACK_DIRECT", "BAND_ONE_ALL", "BAND_BACK_ALL"}
for row in fees.values():
    check(row, [0.7, 0.6], "14")
laws = read("--uncertainty", "1", "3", ".4")
assert set(laws) == {"BASE", "PROPOSAL", "MAXIMIN", "DOMINANT"}
check(laws["BASE"], [0.0, 0.0, 0.0], "04")
for name in ("PROPOSAL", "MAXIMIN", "DOMINANT"):
    check(laws[name], [0.5, 0.7, 0.5], "14")
fragile = read("--uncertainty", "1", "3", ".4", fee=0.35)
check(fragile["PROPOSAL"], [-0.25, 0.45, -0.25], "14")
for name in ("MAXIMIN", "DOMINANT"):
    check(fragile[name], [0.0, 0.0, 0.0], "04")
for args in [("--fee-band", "3", "1"), ("--uncertainty", "1", "3", "1"),
             ("--uncertainty", "1", "nan", ".1")]:
    run = invoke(*args)
    assert run.returncode != 0 and not run.stdout.strip(), (args, run)
