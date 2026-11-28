"""Complete retained production build admission only, no code invocation."""
import argparse,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded
from legacy_build import verify
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--retained",type=Path,required=True);a=p.parse_args()
    print(encoded(verify(a.retained.resolve(strict=True))).decode(),end="")
