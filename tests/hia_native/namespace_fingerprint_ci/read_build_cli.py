"""Inert full native build validation; no loader or native call."""
from pathlib import Path
import argparse,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded
from read_callable_build import verify
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--build",type=Path,required=True)
    a=p.parse_args();print(encoded(verify(a.build.resolve(strict=True))).decode(),end="")
