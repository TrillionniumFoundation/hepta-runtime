"""Capture the registered public Batch graph before any original execution."""
from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-manifest", type=Path, required=True)
    parser.add_argument("--fixture-manifest", type=Path, required=True)
    parser.add_argument("--strace", type=Path, required=True)
    args = parser.parse_args()
    from hia_native_batch_public_pipeline import run_native
    run_native(ROOT, args.output, args.public_manifest, args.fixture_manifest, args.strace)


if __name__ == "__main__":
    main()
