"""Freeze and replay each original fit's first IID DEV capsule, without selection."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


def put(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--capsules", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--compiler-sha256", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sha(args.manifest.read_bytes()) != args.manifest_sha256:
        raise ValueError("reviewed original fixture manifest changed")
    if sha(args.compiler.read_bytes()) != args.compiler_sha256:
        raise ValueError("frozen Python compiler changed")
    if args.cpu not in os.sched_getaffinity(0):
        raise ValueError("requested CPU is unavailable")
    args.output.mkdir()
    queue = []
    for fit in [11, 23, 37, 53, 71]:
        source = args.capsules / f"DEV_{fit}_iid_0.json.gz"
        compressed = source.read_bytes()
        decoded = gzip.decompress(compressed)
        if len(decoded) > 8 * 1024 * 1024:
            raise ValueError("capsule exceeds native bound")
        path = args.output / f"DEV_{fit}_iid_0.json"
        with path.open("xb") as stream:
            stream.write(decoded)
        queue.append(dict(fit=fit, source=str(source.resolve()),
                          compressed_sha256=sha(compressed),
                          decoded_path=str(path.resolve()), decoded_sha256=sha(decoded)))
    root = Path(__file__).resolve().parents[1]
    reader_sources = [root / "Cargo.toml", root / "Cargo.lock", *sorted((root / "src").glob("*.rs"))]
    freeze = dict(schema="hepta.native-fixed-dev-replay-freeze.v1", queue=queue,
                  binary_sha256=sha(args.binary.read_bytes()),
                  reader_sources={str(p.relative_to(root)): sha(p.read_bytes()) for p in reader_sources},
                  script_sha256=sha(Path(__file__).read_bytes()),
                  compiler_sha256=args.compiler_sha256, manifest_sha256=args.manifest_sha256,
                  scope="fixed first IID DEV per original fit; execution qualification, not a new efficacy holdout",
                  monotonic_ns=time.monotonic_ns(), affinity=[args.cpu])
    put(args.output / "QUEUE_FROZEN.json", freeze)
    os.sched_setaffinity(0, {args.cpu})
    results = []
    for row in queue:
        output = args.output / f"fit_{row['fit']}"
        command = [str(args.binary.resolve()), str(args.manifest.resolve()), args.manifest_sha256,
                   str(row["fit"]), row["decoded_path"], row["decoded_sha256"],
                   str(args.compiler.resolve()), args.compiler_sha256, str(output.resolve())]
        start = time.monotonic()
        run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        (args.output / f"fit_{row['fit']}.stdout.json").write_bytes(run.stdout)
        (args.output / f"fit_{row['fit']}.stderr.log").write_bytes(run.stderr)
        record = dict(fit=row["fit"], exit_code=run.returncode,
                      wall_seconds=time.monotonic() - start, command=command)
        if run.returncode == 0:
            record["receipt"] = json.loads(run.stdout)
            record["receipt_sha256"] = sha(run.stdout)
        results.append(record)
    passed = all(row["exit_code"] == 0 for row in results)
    summary = dict(schema="hepta.native-fixed-dev-replay.v1",
                   status="PASS_FIVE_ORIGINAL_SOURCES" if passed else "FAILED",
                   freeze_sha256=sha((args.output / "QUEUE_FROZEN.json").read_bytes()),
                   results=results, production_eligible=False)
    put(args.output / "SUMMARY.json", summary)
    print(json.dumps({"status": summary["status"], "fits": len(results),
                      "summary": str((args.output / "SUMMARY.json").resolve())}))
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
