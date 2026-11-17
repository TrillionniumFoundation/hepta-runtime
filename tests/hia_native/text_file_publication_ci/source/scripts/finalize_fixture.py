#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Observe and retire only interrupted, explicitly owned fixture trees before export."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical, require
from body_cases import cases
from body_filesystem import snapshot,retire
from buffer_store import Writer

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();root=a.output.absolute();fixture=root/"fixtures"
    if not fixture.exists():return
    remaining=sorted(fixture.iterdir())
    if not remaining:
        fixture.rmdir();return
    folder=root/"interrupted-fixtures";require(not folder.exists(),"interrupted fixture capture already exists")
    folder.mkdir();store=Writer(folder/"buffers");lookup={"case-%03d"%r["id"]:r for r in cases()}
    rows=[]
    for path in remaining:
        require(path.is_dir() and not path.is_symlink() and path.name in lookup,"unknown fixture child")
        rows.append(dict(name=path.name,snapshot=snapshot(path,store)))
        retire(path,lookup[path.name])
    fixture.rmdir()
    (folder/"FILES.json").write_bytes(canonical(dict(complete_remaining_state=rows,semantic_reexecuted=False)))

if __name__=="__main__":main()
