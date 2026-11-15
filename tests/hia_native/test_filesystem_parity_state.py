"""Execute the filesystem owner's private continuation and lifecycle controls."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_parity.qualify_state import main

if __name__ == '__main__':
    main()
