"""Copy small input custody records without rewriting any captured evidence."""
from pathlib import Path
import argparse
import shutil

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--input",type=Path,required=True);p.add_argument("--capture",type=Path,required=True);p.add_argument("--label",choices=("build","failure"),required=True);a=p.parse_args()
    a.capture.mkdir(parents=True,exist_ok=True);out=a.capture/("input-custody-"+a.label);out.mkdir()
    for name in ("DOWNLOAD.json","archive.json"):
        if (a.input/name).is_file():shutil.copyfile(a.input/name,out/name)

if __name__=="__main__":main()
