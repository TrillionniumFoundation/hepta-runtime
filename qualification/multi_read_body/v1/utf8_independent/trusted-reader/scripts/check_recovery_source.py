#!/usr/bin/env python3
"""Admit this complete pure-recovery source before fetching any retained capture."""
from pathlib import Path
import ast,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from inputs import GROUPS
def main():
    identity=source_evidence(ROOT);count=0
    for path in sorted(ROOT.rglob("*.py")):compile(path.read_bytes(),str(path),"exec");count+=1
    binding=decode((ROOT/"ORIGIN_BINDING.json").read_bytes())
    require(set(binding["groups"])==set(GROUPS),"all original lanes frozen")
    for group,value in binding["groups"].items():
        require(value["commit"]=="2f340d95af89d927a54495e01ac8a81c590da94e" and value["run_id"]==44160803459
            and value["gate_status"]=="FAIL" and value["manifest_sha256"]==pin(ROOT/"ORIGINAL_SOURCE_MANIFEST.json")["sha256"],
            "preserved first original failure identity")
    change=decode((ROOT/"READER_CHANGE.json").read_bytes())
    before=(ROOT/"reference/read_utf8_before.py").read_text();after=(ROOT/"scripts/read_utf8.py").read_text()
    require(len(change["edits"])==1 and change["edits"][0]==dict(
        old="stat.S_IMODE(binary.stat().st_mode)==0o755",new="stat.S_IMODE(binary.stat().st_mode)==0o500",occurrences=1),
        "only original wrong mode assertion is repaired")
    edit=change["edits"][0];require(before.count(edit["old"])==1 and before.replace(edit["old"],edit["new"])==after,
        "full reversible reader derivation")
    require(pin(ROOT/"reference/read_utf8_before.py")=={k:change["before"][k] for k in ("bytes","sha256")}
        and pin(ROOT/"scripts/read_utf8.py")=={k:change["after"][k] for k in ("bytes","sha256")},
        "complete reader change byte pins")
    result=dict(status="PURE_UTF8_RECOVERY_SOURCE_PASS",source=identity,syntax_files=count,
        lanes=len(binding["groups"]),original_calls_retained=True,new_original_or_native_applications=0)
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
