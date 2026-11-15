#!/usr/bin/env python3
"""CPU behavioral replay of MIT's fixed zero-training Breakout weights.

Uses verbatim MinAtar 1.0.15 environment extracted from the pinned prompt.
That environment is GPL-3.0 (upstream/exp5_write_from_scratch/LICENSE-MinAtar);
network/logs are CC BY 4.0. This independent runner is GPL-3.0 as well.
Episode seeds are new, not the unpublished original seed stream.
"""
import argparse
import hashlib
import json
import os
import re
import time
from concurrent.futures import ProcessPoolExecutor
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
import numpy as np
from replay_public import OUT, checked_read


def load_env():
    prompt = checked_read("exp5_write_from_scratch/runs/breakout/message.txt").decode()
    source = re.search(r"```python\n(.*?)```", prompt, re.S).group(1)
    # Manually inspected pinned source: NumPy and Env only; no file/network IO.
    namespace = {}
    exec(compile(source, "upstream/MinAtar-1.0.15/breakout.py", "exec"), namespace)
    return namespace["Env"], hashlib.sha256(source.encode()).hexdigest()


def episode(job):
    policy, seed, max_steps = job
    Env, _ = load_env()
    env = Env()
    env.random = np.random.RandomState(seed)
    env.reset()
    rng = np.random.default_rng(seed + 0x32ACFD)
    z = np.load(OUT / "breakout_from_zero.npz")
    W1, b1, W2, b2, W3, b3 = (z[k] for k in ("W1", "b1", "W2", "b2", "W3", "b3"))
    if policy == "random_sign":
        # Fixed before any evaluation, same sparse support and tensor norms.
        # This is one control network, not one fitted candidate per episode.
        control_rng = np.random.default_rng(871031)
        W1, b1, W2, b2, W3, b3 = [a * control_rng.choice(np.array([-1., 1.], np.float32), size=a.shape)
                                      for a in (W1, b1, W2, b2, W3, b3)]
    previous = score = 0
    for step in range(max_steps):
        if policy in ("published", "random_sign"):
            # Reward/unused channel weights are zero. Sum 3 active input rows.
            # Same neural policy; no external controller or game-search heuristic.
            pre = (W1[(90 + env.pos) * 6] + W1[(env.ball_y * 10 + env.ball_x) * 6 + 3]
                   + W1[(env.last_y * 10 + env.last_x) * 6 + 4] + b1)
            h1 = np.tanh(pre)
            h2 = np.tanh(h1 @ W2 + b2)
            logits = h2 @ W3 + b3
            prob = np.exp(logits.astype(np.float64) - float(logits.max()))
            prob /= prob.sum()
            a = int(np.searchsorted(np.cumsum(prob), rng.random(), side="right"))
        else:
            a = min(5, int(rng.random() * 6))
        if rng.random() < 0.1:
            a = previous
        previous = a
        reward, done = env.act(a)
        score += reward
        if done:
            break
    return {"policy": policy, "seed": seed, "score": score, "steps": step + 1, "terminal": bool(env.terminal)}


def verify_sparse_forward():
    Env, _ = load_env()
    env = Env()
    env.random = np.random.RandomState(993434)
    env.reset()
    rng = np.random.default_rng(857833)
    z = np.load(OUT / "breakout_from_zero.npz")
    W1, b1, W2, b2, W3, b3 = (z[k] for k in ("W1", "b1", "W2", "b2", "W3", "b3"))
    assert not np.any(W1[2::6]) and not np.any(W1[1::6]) and not np.any(W1[5::6])
    max_error = 0.
    for _ in range(1000):
        state = env.state()
        x = np.zeros((10, 10, 6), dtype=np.float32)
        x[:, :, 0], x[:, :, 2], x[:, :, 3], x[:, :, 4] = state[:, :, 0], state[:, :, 3], state[:, :, 1], state[:, :, 2]
        dense_pre = x.ravel() @ W1 + b1
        pre = (W1[(90 + env.pos) * 6] + W1[(env.ball_y * 10 + env.ball_x) * 6 + 3]
               + W1[(env.last_y * 10 + env.last_x) * 6 + 4] + b1)
        dense_logits = np.tanh(np.tanh(dense_pre) @ W2 + b2) @ W3 + b3
        sparse_logits = np.tanh(np.tanh(pre) @ W2 + b2) @ W3 + b3
        max_error = max(max_error, float(np.max(np.abs(dense_logits - sparse_logits))))
        np.testing.assert_allclose(sparse_logits, dense_logits, rtol=0, atol=1e-4)
        _, done = env.act(int(rng.integers(6)))
        if done:
            env.reset()
    return {"states": 1000, "max_logit_absolute_error": max_error, "tolerance": 1e-4}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    start = time.perf_counter()
    check = verify_sparse_forward()
    _, env_sha = load_env()
    rows = []
    jobs = [(p, 20261103 + i, 10000) for p in ("published", "zero_weight", "random_sign") for i in range(args.episodes)]
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for n, row in enumerate(pool.map(episode, jobs, chunksize=10), 1):
            rows.append(row)
            if n % 100 == 0:
                print(f"Completed {n}/{len(jobs)} episodes; wall {time.perf_counter()-start:.1f}s", flush=True)
    stats = {}
    for p in ("published", "zero_weight", "random_sign"):
        rr = [r for r in rows if r["policy"] == p]
        scores = np.array([r["score"] for r in rr], float)
        se = float(scores.std(ddof=1) / np.sqrt(len(scores)))
        stats[p] = {"episodes": len(scores), "mean_score": float(scores.mean()), "standard_error": se,
                    "normal_95pct_ci": [float(scores.mean()-1.96*se), float(scores.mean()+1.96*se)],
                    "mean_steps": float(np.mean([r["steps"] for r in rr])),
                    "capped_episodes": sum(not r["terminal"] for r in rr)}
    result = {"source_commit": "4d09ba6d6a7e891dd8063974dfe81b3d78e3494f", "environment": "MinAtar 1.0.15 Breakout source embedded in published prompt",
              "environment_source_sha256": env_sha, "sticky_action_probability": 0.1, "max_episode_steps": 10000,
              "actions_sampled_from_softmax": True, "seed_start": 20261103, "training_steps": 0,
              "fitting_or_model_selection": False, "random_control_seed": 871031,
              "random_control": "Fixed random signs; same sparse support and per-tensor Frobenius norms as constructed network",
              "sparse_dense_check": check, "results": stats,
              "wall_seconds": time.perf_counter()-start,
              "claim_boundary": "Independent new-seed behavioral replay of fixed published weights, with zero-weight and norm-matched random-sign controls. PPO checkpoints absent; published PPO comparison not rerun."}
    (OUT / "breakout_behavior_results.json").write_text(json.dumps(result, indent=2) + "\n")
    (OUT / "breakout_episodes.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
