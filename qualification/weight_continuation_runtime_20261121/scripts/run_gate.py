"""Record an actual isolated cargo invocation without overwriting failed attempts."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--toolchain-bin", required=True)
    parser.add_argument("--cargo-home", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("label")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PATH"] = args.toolchain_bin + os.pathsep + env["PATH"]
    env["CARGO_HOME"] = args.cargo_home
    env["CARGO_TARGET_DIR"] = args.target_dir
    env["CARGO_BUILD_JOBS"] = "2"
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    start = time.monotonic()
    log = root / "evidence" / (args.label + ".log")
    with log.open("xb") as output:
        process = subprocess.run(command, cwd=root, env=env, stdout=output,
                                 stderr=subprocess.STDOUT, timeout=600)
    receipt = dict(command=command, exit_code=process.returncode,
                   wall_seconds=time.monotonic() - start, log=log.name,
                   scope="isolated research crate; no production runtime build or registration")
    with (root / "evidence" / (args.label + ".json")).open("x") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    print(json.dumps(receipt))
    print(log.read_text()[-7000:])
    raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
