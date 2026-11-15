"""Check the complete filesystem build and reject corrupted retained bytes."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_parity.qualify_build import main

if __name__ == '__main__':
    main()
