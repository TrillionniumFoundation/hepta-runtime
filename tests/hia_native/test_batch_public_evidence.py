"""Reject physical and consistently resigned native Batch evidence mutations."""
from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from hia_native_batch_public_pipeline import run_native_controls
    run_native_controls(ROOT, args.output)


if __name__ == "__main__":
    main()
