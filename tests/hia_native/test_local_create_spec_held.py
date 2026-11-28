"""Execute all 15 actual held synchronous/poll/mkdir Local Create cases."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'local_create/spec'))
from native_suite import run
if __name__ == '__main__': run('held')
