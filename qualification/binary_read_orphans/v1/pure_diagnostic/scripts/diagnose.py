#!/usr/bin/env python3
"""Read complete retained original/native applications; do not execute either."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from readonly import guarded
import restore_original
def main():
    p=argparse.ArgumentParser();p.add_argument("--semantic",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
    semantic=a.semantic.resolve(strict=True);source=semantic/"original/restored/source";data=semantic/"original/restored/run/application"
    sys.path.insert(0,str(source/"scripts"))
    import read_capture as r
    def read():
        archive=restore_original.verify(ROOT,semantic,restore_original.selection(ROOT,a.group))
        left,lc,lr=r.read_role(source,data,"original",a.group);right,rc,rr=r.read_role(source,data,"native",a.group)
        comparisons=[]
        for old,new in zip(left,right):
            q=old["input"];require(q==new["input"],"same frozen input")
            na,nb=r.Normalize(old["fixture_root"]),r.Normalize(new["fixture_root"])
            require(na.apply(old["setup"])==nb.apply(new["setup"]),"same declared filesystem input")
            require(na.apply(old["actual"]["chain"]["before"])==nb.apply(new["actual"]["chain"]["before"]),"same before state")
            for attempt,(a1,b1)in enumerate(zip(old["actual"]["chain"]["invocations"],new["actual"]["chain"]["invocations"]),1):
                oe=r.original_effects(old,attempt)if q["observer"]else[]
                ne=r.native_effects(new,attempt)if q["observer"]else[]
                r.result_equivalent(a1["result"],b1["result"],oe,ne,q,old,new,na,nb)
                op=na.apply(r.comparison_effects(oe));np=nb.apply(r.comparison_effects(ne))
                diffs=[dict(index=i,original=op[i]if i<len(op)else None,native=np[i]if i<len(np)else None)
                    for i in range(max(len(op),len(np)))if i>=len(op)or i>=len(np)or op[i]!=np[i]]
                comparisons.append(dict(id=q["id"],attempt=attempt,entry=q["entry"],mode=q["mode"],
                    original_root=old["fixture_root"],native_root=new["fixture_root"],differences=diffs,
                    original_effects=oe,native_effects=ne,original_projected=op,native_projected=np))
        return dict(status="COMPLETE_CAPTURE_DIAGNOSTIC_READ_PASS",group=a.group,archive=archive,
            original=lc,native=rc,comparisons=comparisons,applications_executed=0,reader_changed=False)
    value=guarded(read,roots=[ROOT,semantic])
    print(encoded(value).decode(),end="")
if __name__=="__main__":main()
