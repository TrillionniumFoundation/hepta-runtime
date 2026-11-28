#!/usr/bin/env python3
from pathlib import Path
import ast,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import source_evidence,encoded,decode,require
identity=source_evidence(ROOT)
for path in sorted(ROOT.rglob("*.py")):
    raw=path.read_bytes();ast.parse(raw,filename=str(path));compile(raw,str(path),"exec")
from cases import cases
queries=cases()
require(len(queries)==32 and sum(q["attempts"]for q in queries)==34,"same frozen input-only domain")
bound=decode((ROOT/"INPUTS.json").read_bytes())["groups"]
require(set(bound)=={"child-orphans","shm"}and bound["child-orphans"]["expected_completed_original_ids"]==[]
    and bound["shm"]["expected_completed_original_ids"]==[27],"fixed old prefix and unexecuted suffix")
print(encoded(dict(status="SOURCE_ONLY_PASS",source=identity,groups=sorted(bound),application_calls=0)).decode(),end="")
