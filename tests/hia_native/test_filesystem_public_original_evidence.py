"""Run the complete physical SDK evidence controls after the fresh replay."""
from pathlib import Path
import argparse
import os
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    driver = ROOT / "tests/hia_native/filesystem_public/test_native_evidence.py"
    os.chdir(driver.parent)
    os.execv(sys.executable, [sys.executable, "-I", "-B", str(driver),
                             "--plan", str(args.plan.absolute()), "--output", str(args.output.absolute())])


if __name__ == "__main__":
    main()
