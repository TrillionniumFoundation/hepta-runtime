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

# Exercise the scalar planner through the same executable that consumers call.
q_graph = ("HEPTA_DAG_V1 2 0\n0 3 0 0 0 0 1 0 1 1 1 .1 0 0\n"
           "1 16 0 .8 0 4 4 4 0 0 0\nHEPTA_Q_SCORES_V1\n"
           "0 -.125 3 9 7 8\n2 7 8 9 .8 -.8\n")
def plan(graph, radius):
    return subprocess.run([*sys.argv[1:], "--plan-q-bias", "1", "2", radius],
                          input=graph, capture_output=True, text=True)
response = plan(q_graph, ".25")
response.check_returncode()
name, delta, lower, upper, cells, actions = response.stdout.split()
assert (name, float(delta), int(cells), actions) == ("Q_BIAS_PLAN", .1875, 2, "14")
assert math.isclose(float(lower), .7) and math.isclose(float(upper), .6)
assert plan(q_graph, ".125").stdout.split()[-1] == "04"
assert plan(q_graph.replace("-.125", "1"), ".25").returncode != 0

# Realized candidate actions may differ from predicted actions after an F64 write.
verification_graph = q_graph.split("HEPTA_Q_SCORES_V1")[0]
def verify_candidate(graph, upper):
    proc = subprocess.run([*sys.argv[1:], "--verify-q-bias", "1", upper], input=graph,
                          capture_output=True, text=True, check=True)
    status, low, high, mismatches, actions = proc.stdout.split()
    return status, float(low), float(high), int(mismatches), actions
state, lower, upper, mismatches, actions = verify_candidate(verification_graph, "2")
assert (state, mismatches, actions) == ("Q_BIAS_VERIFIED", 1, "14")
assert math.isclose(lower,.7) and math.isclose(upper,.6)
assert verify_candidate(verification_graph,"10")[::3] == ("Q_BIAS_REJECT", 1)
assert verify_candidate(verification_graph,"10")[-1] == "04"
same = verification_graph.replace("0 1 0 1 1 1 .1", "0 0 1 1 1 1 .1")
assert verify_candidate(same,"2") == ("Q_BIAS_KEEP",0.,0.,1,"04")

# Closed radius endpoints and isolated exact ties can be the only improving
# scalar policies. Exercise them through both the standalone and shipped CLI.
closed_cases = [
    (".125", .125, "14", [.7, .6],
     "HEPTA_DAG_V1 2 0\n0 18 0 0 0 4 1 4 1 1 1 .1 0 0\n"
     "1 16 0 .8 0 4 4 4 0 0 0\nHEPTA_Q_SCORES_V1\n"
     "-1 0 -1 -1 .125 -1\n2 7 8 9 .8 -.8\n"),
    (".125", -.125, "04", [.9, 1.],
     "HEPTA_DAG_V1 2 0\n0 3 .8 0 0 1 0 1 1 1 1 .1 0 0\n"
     "1 16 0 0 0 4 4 4 0 0 0\nHEPTA_Q_SCORES_V1\n"
     "-.125 0 -1 -1 -1 -1\n0 0 0 0 1 0\n"),
    (".25", .125, "100", [.7, .6],
     "HEPTA_DAG_V1 3 0\n0 18 0 0 0 4 1 4 1 1 1 .1 0 0\n"
     "1 3 .8 0 0 0 0 0 1 1 2 .1 0 0\n"
     "2 1 0 0 0 0 0 0 0 0 0\nHEPTA_Q_SCORES_V1\n"
     "-1 0 -1 -1 .125 -1\n.125 0 -1 -1 -1 -1\n0 -1 -1 -1 -1 -1\n"),
]
for radius, expected_shift, expected_actions, expected_gains, graph in closed_cases:
    response = plan(graph, radius)
    response.check_returncode()
    name, shift, low, high, _, actions = response.stdout.split()
    assert (name, float(shift), actions) == ("Q_BIAS_PLAN", expected_shift, expected_actions)
    assert all(math.isclose(float(a), b, abs_tol=1e-12)
               for a, b in zip((low, high), expected_gains))
