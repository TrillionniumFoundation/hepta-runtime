"""Execute the source-owned public/observer capture, without a Rust reference."""
from pathlib import Path
import argparse
import os
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--public-manifest", required=True, type=Path)
    parser.add_argument("--fixture-manifest", required=True, type=Path)
    parser.add_argument("--strace", required=True, type=Path)
    args = parser.parse_args()
    from hia_native_filesystem_public_pipeline import prepare_native, producer_command, invocation
    output = args.output.absolute()
    prepare_native(ROOT, output, args.public_manifest.absolute(), args.fixture_manifest.absolute())
    command = producer_command(ROOT, output, args.public_manifest.absolute(), args.fixture_manifest.absolute(), args.strace.absolute())
    invocation(ROOT, output, "native", sys.argv, command)
    # Preserve one actual qualification process and its full stdout/stderr.
    # The exec'd source records its own argv, PID, cgroup and complete children.
    os.chdir(ROOT / "tests/hia_native/filesystem_public")
    os.execv(sys.executable, command)


if __name__ == "__main__":
    main()
