"""Execute the unchanged SDK replay at the admitted native fixture's path."""
from pathlib import Path
import argparse
import os
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    parser.add_argument("--cargo", required=True, type=Path)
    parser.add_argument("--strace", required=True, type=Path)
    args = parser.parse_args()
    from hia_native_filesystem_public_pipeline import original_command, invocation, DRIVERS
    command = original_command(ROOT, args.output.absolute(), args.rustc.absolute(), args.cargo.absolute(), args.strace.absolute())
    invocation(ROOT, args.output.absolute(), "original", sys.argv, command)
    os.chdir(ROOT / DRIVERS)
    os.execv(sys.executable, command)


if __name__ == "__main__":
    main()
