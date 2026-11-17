#!/usr/bin/env python3
"""Pure syntax, before-image and frozen-domain admission; no captured app executes."""
from pathlib import Path
import ast,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,require,source_evidence,decode,pin
from cases import cases
from read_retained import reader_contract
def main():
    identity=source_evidence(ROOT);sources=[]
    for path in sorted(ROOT.rglob("*.py")):
        raw=path.read_bytes();ast.parse(raw,filename=str(path));compile(raw,str(path),"exec")
        sources.append(dict(path=path.relative_to(ROOT).as_posix(),**pin(path)))
    contract=reader_contract(ROOT);queries=cases();groups={}
    for q in queries:groups.setdefault(q["group"],[]).append(q["id"])
    require(len(queries)==45 and sum(q["attempts"]for q in queries)==49 and len(groups)==13,
        "unchanged original input domain")
    bound=decode((ROOT/"INPUTS.json").read_bytes())
    require(set(bound["groups"])==set(groups)and sum(x["gate_status"]=="PASS"for x in bound["groups"].values())==7
        and sum(x["gate_status"]=="FAIL"for x in bound["groups"].values())==6,"all original archives, including failures")
    require((ROOT/"scripts/cases.py").read_bytes()==(ROOT/"trusted-qualification/scripts/cases.py").read_bytes(),
        "input bytes changed after application capture")
    report=dict(status="READ_ORPHANS_SOURCE_AND_INPUT_ONLY_PASS",source=identity,python_sources=sources,
        observed_inputs=40,observer_off_inputs=5,entry_invocations=49,groups=groups,contract=contract,
        read_function_calls=0,hia_calls=0,rust_calls=0,fixture_effects=0)
    print(encoded(report).decode(),end="")
if __name__=="__main__":main()
