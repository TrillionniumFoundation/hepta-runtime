#!/usr/bin/env python3
from pathlib import Path
import json,sys
sys.dont_write_bytecode=True;sys.path.insert(0,str(Path(__file__).resolve().parent))
from async_build_common import *
def main():
    result=package();trans=doc(HERE/"READER_TRANSFORMS.json");text=raw(HERE.parent/"previous-build/read_build.py").decode()
    require(pin(HERE.parent/"previous-build/read_build.py")=={k:trans["source"][k] for k in ("bytes","sha256")},"exact prior full reader")
    for row in trans["edits"]:
        require(text.count(row["before"])==1,"unique complete reader transformation")
        text=text.replace(row["before"],row["after"])
    require(text.encode()==raw(HERE/"read_build.py"),"entire reader transformation")
    print(json.dumps(dict(status="SOURCE_ONLY_PASS",source=result,reader_exact_transforms=len(trans["edits"])),sort_keys=True))
if __name__=="__main__":main()
