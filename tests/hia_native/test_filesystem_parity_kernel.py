"""Capture every real native filesystem case before original replay."""
from pathlib import Path
import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_parity.capture_native import main

if __name__ == '__main__':
    previous = os.umask(0o077)
    try:
        main()
    finally:
        os.umask(previous)
