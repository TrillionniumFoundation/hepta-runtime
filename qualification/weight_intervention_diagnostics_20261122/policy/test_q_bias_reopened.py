#!/usr/bin/env python3
"""Shipped-CLI regressions for bounded plans and complete reopened selection.

The tiny graph is an explicit engineering control, not a research checkpoint.
Only reopened action vectors enter selection; predicted gains never adopt an edit.
"""
import math
import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import tempfile

COMMAND = sys.argv[1:]
GRAPH = """HEPTA_DAG_V1 2 0
0 18 0 0 0 4 1 4 1 1 1 .1 0 0
1 16 0 .8 0 4 4 4 0 0 0
HEPTA_Q_SCORES_V1
-1 0 -1 -1 .125 -1
2 7 8 9 .8 -.8
"""
PARAMETERS = ["1", "2", ".25", "2"]
CHECKS = 0


def invoke(mode, text, parameters=PARAMETERS, okay=True):
    global CHECKS
    result = subprocess.run(COMMAND + [mode] + parameters, input=text, text=True,
                            capture_output=True, check=False)
    assert (result.returncode == 0) == okay, (result.returncode, result.stdout, result.stderr)
    CHECKS += 1
    return result.stdout.splitlines()


def select(rows, text=GRAPH, parameters=PARAMETERS, okay=True):
    return invoke("--select-q-bias-candidates", text + "HEPTA_Q_REOPENED_V1\n" + rows,
                  parameters, okay)


plan = invoke("--plan-q-bias-candidates", GRAPH)
assert plan[0].split() == ["Q_BIAS_CANDIDATES_V1", "2", "2", "5"]
first, second = [line.split() for line in plan[1:]]
assert first[1:3] == ["1", "BOUNDARY"] and float(first[3]) == .125
assert second[1:3] == ["2", "INTERIOR"] and float(second[3]) == .1875
assert first[-1] == second[-1] == "14", "equal predicted policies must retain distinct shifts"

# Realized rounding/error control: the smaller shift did not change the actual policy.
result = select("2 .125 44 .1875 14")[0].split()
assert result[:2] == ["Q_BIAS_SELECTED", "2"] and result[-1] == "14"
assert math.isclose(float(result[3]), .7) and math.isclose(float(result[4]), .6)
# When both actual policies keep the incumbent, a predicted gain cannot authorize selection.
assert select("2 .125 44 .1875 44")[0].startswith("Q_BIAS_KEEP 0 ")
assert select("2 .125 FAILED .1875 14")[0].startswith("Q_BIAS_SELECTED 2 ")
assert select("2 .125 FAILED .1875 FAILED")[0].startswith("Q_BIAS_KEEP 0 ")
assert select("2 .125 14 .1875 14")[0].startswith("Q_BIAS_SELECTED 1 ")

for rows in ("0", "1 .125 14", "2 .125 14", "2 .125 14 .1875 19",
             "2 .1875 14 .125 14", "2 .125 14 .1875 14 extra", "2 NaN 14 .1875 14",
             "2 .125 14 .1875 1", "2 .125 14 .1875 44é"):
    select(rows, okay=False)
for limit in ("0", "1", "65", "2.5", "NaN", "inf"):
    invoke("--plan-q-bias-candidates", GRAPH, ["1", "2", ".25", limit], okay=False)

# The plan is regenerated using the exact same law, fees, radius and scores.
select("2 .125 14 .1875 14", parameters=["1", "10", ".25", "2"], okay=False)
assert select("0", parameters=["1", "10", ".25", "2"])[0].endswith("44")

# Physical F64 rounding counterexample, frozen independently of the research data.
# The bias addition rounds before the forward sum. The exact mathematical cut
# predicts action 1, but the reopened parameter still produces action 4.
constant = -0.06358258106565634
bias = 0.15391577434753906
stop = 0.09078237381574712
old_score = constant + bias
cut = stop - old_score
tiny = GRAPH.replace("-1 0 -1 -1 .125 -1", f"-1 {old_score!r} -1 -1 {stop!r} -1")
physical_plan = invoke("--plan-q-bias-candidates", tiny)
members = [line.split() for line in physical_plan[1:]]
assert float(members[0][3]) == cut and members[0][2] == "BOUNDARY"
assert members[1][2] == "INTERIOR"
legacy = invoke("--plan-q-bias", tiny, ["1", "2", ".25"])[0].split()
assert float(legacy[1]) == cut
header = json.dumps({"bias": {"dtype": "F64", "shape": [3], "data_offsets": [0, 24]}},
                    separators=(",", ":")).encode()
header += b" " * (-len(header) % 8)
offset = len(header) + 8
original = struct.pack("<Q", len(header)) + header + struct.pack("<3d", bias, .2, -.3)
original_sha = hashlib.sha256(original).hexdigest()
actual_rows = []
with tempfile.TemporaryDirectory(prefix="q-bias-reopened-") as directory:
    path = pathlib.Path(directory) / "isolated.safetensors"
    for row in members:
        shift = float(row[3])
        values = struct.unpack("<3d", original[offset:])
        candidate = original[:offset] + struct.pack("<3d", *(v + shift for v in values))
        assert candidate[:offset] == original[:offset] and len(candidate) == len(original)
        path.write_bytes(candidate)
        reopened = path.read_bytes()
        assert reopened == candidate
        actual_score = constant + struct.unpack_from("<d", reopened, offset)[0]
        actions = "14" if actual_score >= stop else "44"
        actual_rows.append(f"{shift:.17e} {actions}")
        path.write_bytes(reopened[:offset] + original[offset:])
        assert path.read_bytes() == original
        assert hashlib.sha256(path.read_bytes()).hexdigest() == original_sha
assert actual_rows[0].endswith("44") and actual_rows[1].endswith("14")
physical_result = select("2\n" + "\n".join(actual_rows), text=tiny)[0].split()
assert physical_result[:2] == ["Q_BIAS_SELECTED", "2"]
assert math.isclose(float(physical_result[3]), .7) and math.isclose(float(physical_result[4]), .6)
print(json.dumps({"synthetic_F64_shortfall": stop - (constant + (bias + cut)),
                  "mathematical_winner": "BOUNDARY", "reopened_winner": "INTERIOR",
                  "physical_candidates": 2, "rollback_full_SHA_equal": True,
                  "research_checkpoint": False}))
print(f"bounded plan and reopened selection: {CHECKS} entry-point checks passed")
