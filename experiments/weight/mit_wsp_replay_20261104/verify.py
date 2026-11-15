# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Verify the retained replay evidence and reproduce the recorded editor-cost sum."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import statistics

import acquire

ROOT = Path(__file__).resolve().parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def close(actual: float, expected: float, label: str) -> None:
    require(math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12), label)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    acquisition = acquire.acquire(None, True)
    aggregate = json.loads((ROOT / "aggregate.json").read_text())
    require(digest(ROOT / "audit_and_replay.py") == aggregate["executed_script_sha256"], "executed script changed")
    require(digest(ROOT / "acquire_manifest.json") == aggregate["acquisition_manifest_sha256"], "input manifest changed")
    full = ROOT / acquire.relative_path(aggregate["full_result_path"])
    require(digest(full) == aggregate["full_result_sha256"], "retained replay result changed")
    report = json.loads(full.read_text())
    published = json.loads((ROOT / "upstream/exp5_write_from_scratch/eval/minatar_eval.json").read_text())
    episodes = evaluations = 0
    wall = cpu = 0.0
    for game, record in report["games"].items():
        expected = aggregate["games"][game]
        require(record["reconstruction"] == expected["reconstruction"], "reconstruction receipt differs")
        require(expected["authors_1000_episode_result"] == published[game]["hand"], "author result differs")
        for run in record["runs"]:
            compact = {k: v for k, v in run.items() if k not in ("scores", "lengths", "game", "mode")}
            require(compact == expected["variants"][run["mode"]], "aggregate variant differs")
            scores, lengths = run["scores"], run["lengths"]
            require(len(scores) == len(lengths) == run["episodes"], "episode count differs")
            close(statistics.mean(scores), run["mean"], "mean score differs")
            close(statistics.stdev(scores) / math.sqrt(len(scores)), run["standard_error"], "standard error differs")
            close(statistics.mean(lengths), run["mean_steps"], "mean length differs")
            close(sum(n == 10000 for n in lengths) / len(lengths), run["cut_share"], "cut share differs")
            require(sum(lengths) == run["forward_calls"], "policy evaluation count differs")
            episodes += len(scores)
            evaluations += sum(lengths)
            wall += run["elapsed_seconds"]
            cpu += run["cpu_seconds"]
    totals = aggregate["totals"]
    require(episodes == totals["episodes"] and evaluations == totals["policy_action_evaluations"], "totals differ")
    close(wall, totals["wall_seconds"], "wall total differs")
    close(cpu, totals["cpu_seconds"], "CPU total differs")
    turns = {}
    for turn in [40, 41, 80, 81, 120, 121, 158]:
        path = ROOT / f"upstream/exp8_math/runs/p50c/turns/t{turn:03}/run.json"
        turns[turn] = json.loads(path.read_text())
    endings = [turns[turn]["audit"] for turn in [40, 80, 120, 158]]
    require(len({record["thread_id"] for record in endings}) == 4, "expected four different editor conversations")
    for previous, start, end in [(40, 41, 80), (80, 81, 120), (120, 121, 158)]:
        require(turns[previous]["audit"]["thread_id"] != turns[start]["audit"]["thread_id"], "missing conversation boundary")
        require(turns[start]["audit"]["thread_id"] == turns[end]["audit"]["thread_id"], "ending belongs to a different conversation")
        for key, value in turns[start]["audit"]["usage"].items():
            require(value <= turns[end]["audit"]["usage"][key], "cumulative usage decreased")
    usage = {key: sum(record["usage"][key] for record in endings) for key in endings[0]["usage"]}
    usage["uncached_input_tokens"] = usage["input_tokens"] - usage["cached_input_tokens"]
    require(usage == aggregate["original_p50c_editor_recorded_usage"], "editor cost sum differs")
    print(json.dumps({"status": "passed", "acquisition": acquisition,
                      "episode_statistics_verified": episodes, "editor_recorded_usage": usage,
                      "scope": "artifact identity and independent arithmetic verification; no new inference"}, indent=2))


if __name__ == "__main__":
    main()
