"""Run one complete source-owned request-registry native domain."""
from pathlib import Path
import os,sys
ROOT=Path(__file__).resolve().parents[2]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_request_registry_pipeline import run_native
if __name__=='__main__':
 run_native(ROOT,Path(os.environ['HIA_REQUEST_REGISTRY_OUTPUT']),'sdk')
