"""Run every unchanged ordinary pair with portable source-bound build admission."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from portable_support import configure, source_evidence

if __name__ == '__main__':
    source_evidence()
    configure().main()
