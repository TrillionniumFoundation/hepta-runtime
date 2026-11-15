"""Execute one complete actual HIA Bellman qualification domain."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_bellman_qualification import run_native
if __name__ == "__main__":
    run_native('bellman')
