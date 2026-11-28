"""Read all retained fixture/model and original/native comparisons without execution."""
from pathlib import Path
import argparse,hashlib,json,sys
sys.dont_write_bytecode=True
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def compact(value):
    if isinstance(value,str) and len(value)>200:return dict(bytes=len(value),sha256=hashlib.sha256(value.encode()).hexdigest(),prefix=value[:120])
    if isinstance(value,list):return [compact(v) for v in value]
    if isinstance(value,dict):return {k:compact(v) for k,v in value.items()}
    return value
def run(prior,output):
    sys.path.insert(0,str(prior/"source"))
    import common,read_original,protocol
    assert common.source()=="925dede1dfdd747371c7101ad3cb7a2075e59c57d6326312737c71098ff9ecbf"
    root=prior/"run/semantic";domain=protocol.cases(common.ROOT)
    observed=common.loads(common.read(root/"native-observed/OBSERVATIONS.json"))
    original=common.loads(common.read(root/"original/OBSERVATIONS.json"))
    meta=common.loads(common.read(root/"CAPTURE.json"))
    mismatches=[];semantic=[];trees=[];count=0
    for ci,case in enumerate(domain):
        for si,step in enumerate(case["steps"]):
            nr=observed[count];rr=original[count];count+=1
            assert nr["case"]==rr["case"]==ci and nr["step"]==rr["step"]==si
            expected=read_original.model(case,case["steps"][:si+1],meta["uid"],meta["gid"])
            for label,row in (("native",nr),("original",rr)):
                before=read_original.complete(row["before"]);after=read_original.complete(row["after"])
                if not before==after==expected:
                    mismatches.append(dict(case=ci,name=case["name"],step=si,cohort=label,expected=expected,before=before,after=after))
            if nr["semantic_hex"]!=rr["semantic_hex"]:
                semantic.append(dict(case=ci,name=case["name"],step=si,native=nr["semantic_hex"],original=rr["semantic_hex"]))
            if any(read_original.complete(nr[k])!=read_original.complete(rr[k]) for k in ("before","after")):
                trees.append(dict(case=ci,name=case["name"],step=si,native=nr,original=rr))
    result=dict(status="PURE_CAPTURE_DIAGNOSIS",operations=count,model_mismatches=mismatches,semantic_mismatches=semantic,tree_mismatches=trees,native_executions=0,rust_executions=0)
    output.write_bytes(enc(result));print(enc(compact(result)).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--prior",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();run(a.prior,a.output)
