"""Fresh unchanged SDK replay after the complete registered native admission."""
from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


def main():
    parser = argparse.ArgumentParser()
    for name in ("output", "rustc", "cargo", "strace"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    from hia_native_batch_public_pipeline import run_original
    run_original(ROOT, args.output, args.rustc, args.cargo, args.strace)


if __name__ == "__main__":
    main()
