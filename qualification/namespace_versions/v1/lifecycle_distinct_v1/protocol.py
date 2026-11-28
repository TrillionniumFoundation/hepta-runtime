"""Frozen complete namespace process inputs, never an implementation oracle."""
import json
from common import ROOT,loads,read,require
def domain(root=ROOT):
    d=loads(read(root/"DOMAIN.json"))
    require(d["schema"]=="hepta.namespace-versions.actual-domain.v1"and d["completed_or_unknown_application_replays"]==0,
        "entire actual namespace domain")
    require(len(d["groups"])==len(d["cases"])==2 and d["operations"]==sum(len(c["steps"])for c in d["cases"])==324,
        "complete frozen lifecycle groups and source operations")
    require(d["groups"]==[c["group"]for c in d["cases"]]and[c["case"]for c in d["cases"]]==list(range(2)),
        "one fresh complete case per actual process group")
    parallel=sum(s["operation"]["workers"]*s["operation"].get("count",1)for c in d["cases"]for s in c["steps"]if
        s["operation"]["op"]in("parallel-read","parallel-new"))
    require(parallel==d["parallel_calls"]==16 and d["comparison"]["same_physical_tree"]is True
        and d["comparison"]["roles"]==["original","native-observed","native-off"],"all exact real concurrent calls")
    for case in d["cases"]:
        for r in case["relations"]:
            require(r["kind"]in("same_token","different_tokens","concurrent_id_bijection"),"whole frozen relation kind admitted before applications")
            if r["kind"]=="concurrent_id_bijection":
                require(r["count"]==16 and r["sid_first"]==17,"exact distinct concurrent domain")
            else:require(r["steps"]and all(type(i)is int and 0<=i<len(case["steps"])for i in r["steps"]),"all complete source relation indices")
    return d
def cases(group,root=ROOT):
    d=domain(root);require(group in d["groups"],"source-defined fresh process group")
    return[c for c in d["cases"]if c["group"]==group]
def line(value):return(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
def require_semantic(v):
    require(type(v)is dict and set(v)=={"kind","family","code","version","digest"}and
        all(type(v[k])is int for k in("kind","family","code"))and v["kind"]in range(4),"all precise source result fields")
    if v["kind"]==3:
        require(v["version"]is None and v["digest"]is None and(v["family"]==1 and 0<=v["code"]<=4095 or
            v["family"]==2 and 1<=v["code"]<=11),"all actual OS and original literal errors")
    else:
        require(v["family"]==v["code"]==0,"successful result has no original error")
        if v["kind"]==1:
            require(type(v["version"])is list and len(v["version"])==2 and all(type(x)is int and 0<=x<1<<64 for x in v["version"])
                and v["digest"]is None,"whole low-half and composite set tokens")
        elif v["kind"]==2:
            require(v["version"]is None and type(v["digest"])is str and len(v["digest"])==64 and
                bytes.fromhex(v["digest"]).hex()==v["digest"],"whole original fingerprint bytes")
        else:require(v["version"]is None and v["digest"]is None,"exact optional no-value")
    return v
