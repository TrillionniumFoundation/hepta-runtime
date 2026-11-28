"""Materialize new physical mutations outside each strict read-only check."""
from pathlib import Path
import argparse,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded
import reader_cli,reader_controls
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--capture",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    reader_cli.prepare()
    value=reader_controls.run(a.capture.resolve(strict=True),a.output.absolute())
    print(encoded(value).decode(),end="")
