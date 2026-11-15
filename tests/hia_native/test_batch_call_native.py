"""Main entry for the actual frozen Batch private and three-partition producer."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from hia_native_batch_call_pipeline import run_native
if __name__=='__main__':run_native()
