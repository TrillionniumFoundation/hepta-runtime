"""Invoke only the exact original producer's frozen read-only evidence reader."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
p=argparse.ArgumentParser();p.add_argument("--capture",type=Path,required=True);a=p.parse_args()
capture=a.capture.resolve(strict=True);package=capture/"ci-package"
sys.path[:0]=[str(package/"ci"),str(package/"reference")]
import read_gate
result=read_gate.guarded(package,capture,"1a4adcaa1cc94e544f52d63ca3734c05282849be3d673ab6484eb06450840c34")
print(json.dumps(result,sort_keys=True))
