#!/usr/bin/env python3
"""Two independent complete sessions, each retaining the original 180 s gate."""
from pathlib import Path
import argparse
import json
import sys
from receipt_support import ROOT, PIN, regular, put, process
from read_files import read_capture, compare, retire, check_retired


def run(native, original, output):
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    fixture = output / "fixture-shared"
    report = {"schema": "hepta.runtime.rebuilt-batch-body-pair.v1", "status": "RUNNING",
        "cases_per_side": 926, "same_fixture": str(fixture), "process_names": [],
        "native_binary": dict(path=str(Path(native).resolve(strict=True)), **PIN(regular(native))),
        "original_binary": dict(path=str(Path(original).resolve(strict=True)), **PIN(regular(original))),
        "public_batch_qualified": False, "full_async_cancellation_qualified": False}
    put(output / "result.json", report)
    try:
        for lane, binary in (("native", native), ("original", original)):
            argv = [sys.executable, "-B", str(ROOT / "run_file_lane.py"), "--binary", str(Path(binary).resolve(strict=True)),
                    "--fixture", str(fixture), "--output", str(output / lane)]
            process(output / "processes", lane, argv, cwd=ROOT, timeout=180)
            report["process_names"].append(lane)
            read_capture(output / lane, native=lane == "native")
            retire(output / lane, fixture)
            check_retired(output / lane)
            put(output / "result.json", report)
        result = compare(output / "native", output / "original")
        put(output / "complete-comparison.json", result)
        report.update(status="PASS", comparison=result,
            comparison_pin=PIN(regular(output / "complete-comparison.json")))
        put(output / "result.json", report)
        return report
    except BaseException as error:
        report.update(status="FAIL", failure=repr(error))
        put(output / "result.json", report)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.native, args.original, args.output)
    print(json.dumps({"status": result["status"], "comparison": result["comparison"]}, sort_keys=True))
