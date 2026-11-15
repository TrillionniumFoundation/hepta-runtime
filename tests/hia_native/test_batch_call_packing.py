"""Main entry for actual HIA packing and physical source-contract controls."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from hia_native_batch_call_pipeline import run_packing
if __name__=='__main__':run_packing()
