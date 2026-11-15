"""Execute the complete native typed Bellman commitment domain."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_bellman_commitment_qualification import run_native
if __name__ == "__main__":
    run_native()
