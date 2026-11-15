"""Run bounded paired teacher-forced inference using the published MIT contexts.

This tests the published repetition mechanism on public diagnostic texts. It is
not independent discovery, a MATH-500 score, or an out-of-sample capability claim.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import resource
import time

import numpy as np

try:
    from .acquire import digest
    from .qwen_adapter import load
except ImportError:
    from acquire import digest
    from qwen_adapter import load


def write_new(path, value):
    payload = json.dumps(value, indent=2, allow_nan=False) + "\n"
    with Path(path).open("x") as stream:
        stream.write(payload)


def score_text(provider, text, bound):
    torch = provider.torch
    start = time.monotonic()
    output = provider.forward({"texts": [text]})
    ids = output["input_ids"][0]
    if len(ids) != bound["length"]:
        raise ValueError(f"tokenizer mismatch: published {bound['length']}, observed {len(ids)}")
    with torch.inference_mode():
        logits = output["logits"][0, :-1].float()
        values = logits.gather(1, ids[1:].unsqueeze(1)).squeeze(1) - logits.logsumexp(dim=1)
        values = values.cpu().numpy()
    begin, end = bound["start"] - 1, bound["length"] - 1
    if not 0 <= begin < end <= len(values) or not np.isfinite(values).all():
        raise ValueError("invalid aligned score span or non-finite inference output")
    return {"case": bound["case"], "condition": bound["condition"],
            "input_tokens": len(ids), "scored_branch_tokens": end - begin,
            "branch_mean_logprob": float(values[begin:end].mean()),
            "last_token_logprob": float(values[-1]),
            "input_ids_sha256": hashlib.sha256(ids.cpu().numpy().astype("<i8").tobytes()).hexdigest(),
            "elapsed_seconds": time.monotonic() - start}, values


def run(args):
    root, out = Path(args.root).resolve(), Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    request = json.loads((root / "source/teacher_forced_request.json").read_text())
    bounds = json.loads((root / "source/transfer_probe_bounds.json").read_text())
    if len(request["texts"]) != 14 or len(bounds) != 14 or not 1 <= args.pairs <= 6:
        raise ValueError("unexpected diagnostic fixture or pair count")
    selected = list(range(args.pairs * 2)) + ([12, 13] if args.closure_controls else [])
    plan = {"schema": "hepta.mit_qwen.plan.v1", "created": datetime.now(timezone.utc).isoformat(),
            "reference_root": str(root), "selected_text_indices": selected, "device": args.device,
            "threads": args.threads, "max_sequence": 256, "max_wall_seconds": args.max_seconds,
            "generation_requested": False, "expected_forward_calls": 2 * len(selected),
            "mechanism_gate": {"mean_repetitive_delta_below": -0.02,
                               "abs_productive_delta_below_abs_repetitive_delta": True},
            "scope": "Replay of published teacher-forced diagnostic contexts; no benchmark accuracy inference",
            "source_files": {p.name: digest(p) for p in Path(__file__).parent.glob("*.py")}}
    write_new(out / "plan.json", plan)
    start, provider = time.monotonic(), None
    events, token_arrays = [], {}
    report = {"schema": "hepta.mit_qwen.replay.v1", "status": "running", "plan": plan}
    try:
        provider = load({"reference_root": str(root), "device": args.device, "threads": args.threads,
                         "max_batch": 1, "max_sequence": 256})
        report["load_seconds"] = time.monotonic() - start
        report["provider"] = provider.describe()
        report["verification"] = provider.verification
        for variant in ("base", "edited"):
            provider.set_reference_variant(variant)
            for index in selected:
                if time.monotonic() - start > args.max_seconds:
                    raise TimeoutError("declared replay wall budget exhausted between forwards")
                row, values = score_text(provider, request["texts"][index], bounds[index])
                row.update(variant=variant, text_index=index)
                events.append(row)
                token_arrays[f"{variant}_{index}"] = values
                with (out / "events.jsonl").open("a") as stream:
                    stream.write(json.dumps(row, allow_nan=False) + "\n")
                print(json.dumps(row, allow_nan=False), flush=True)
        paired = []
        for index in selected:
            base = next(x for x in events if x["variant"] == "base" and x["text_index"] == index)
            edited = next(x for x in events if x["variant"] == "edited" and x["text_index"] == index)
            if base["input_ids_sha256"] != edited["input_ids_sha256"]:
                raise ValueError("paired tokenization changed")
            paired.append({"text_index": index, "case": base["case"], "condition": base["condition"],
                           "base_branch_logprob": base["branch_mean_logprob"],
                           "edited_branch_logprob": edited["branch_mean_logprob"],
                           "delta": edited["branch_mean_logprob"] - base["branch_mean_logprob"],
                           "base_last_token_logprob": base["last_token_logprob"],
                           "edited_last_token_logprob": edited["last_token_logprob"]})
        means = {condition: float(np.mean([x["delta"] for x in paired if x["condition"] == condition]))
                 for condition in ("productive", "repetitive")}
        gate = means["repetitive"] < -0.02 and abs(means["productive"]) < abs(means["repetitive"])
        report.update(status="completed", paired=paired, mean_deltas=means,
                      mechanism_gate_passed=gate, capability_improvement_established=False)
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)},
                      mechanism_gate_passed=False, capability_improvement_established=False)
    finally:
        if provider is not None:
            provider.close()
        if token_arrays:
            np.savez_compressed(out / "token_logprobs.npz", **token_arrays)
        report["cost"] = {"elapsed_seconds": time.monotonic() - start,
                          "completed_forward_calls": len(events),
                          "input_token_evaluations": sum(x["input_tokens"] for x in events),
                          "scored_branch_token_evaluations": sum(x["scored_branch_tokens"] for x in events),
                          "generated_tokens": 0, "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                          "platform": platform.platform()}
        write_new(out / "report.json", report)
        print(json.dumps({"status": report["status"], "mechanism_gate_passed": report["mechanism_gate_passed"],
                          "report": str(out / "report.json"), "cost": report["cost"]}), flush=True)
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--pairs", type=int, default=1)
    parser.add_argument("--closure-controls", action="store_true")
    parser.add_argument("--device", choices=["cpu", "cuda:0"], default="cpu")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--max-seconds", type=int, default=300)
    raise SystemExit(run(parser.parse_args()))
