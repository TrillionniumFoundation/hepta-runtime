"""Fixed inputs and complete physical line framing, never an expected implementation."""
import json
from common import ROOT,loads,read,require
def domain(root=ROOT):
    d=loads(read(root/"DOMAIN.json"))
    require(d["schema"]=="hepta.namespace-watcher.semantic-domain.v1" and
        d["same_physical_tree"]is True and d["roles"]==["original","native-observed","native-off"],
        "same complete physical domain")
    require(d["total_cases"]==len(d["cases"])==58 and
        d["total_operations"]==sum(len(c["steps"])for c in d["cases"])==984,
        "complete frozen Watcher case/operation domain")
    require([c["case"]for c in d["cases"]]==list(range(58)) and
        d["groups"]==list(dict.fromkeys(c["group"]for c in d["cases"])) and
        d["max_roots"]==max(len(c["roots"])for c in d["cases"])==260,
        "complete ordered independent group domain")
    return d
def cases(group,root=ROOT):
    d=domain(root);require(group in d["groups"],"fixed process group")
    return[c for c in d["cases"]if c["group"]==group]
def line(value):return(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
def require_semantic(v):
    require(type(v)is dict and set(v)=={"kind","family","code","version"} and
        all(type(v[k])is int for k in("kind","family","code"))and v["kind"]in(0,1),
        "exact semantic result fields")
    if v["kind"]==0:
        require(v["family"]==v["code"]==0 and(v["version"]is None or
            type(v["version"])is list and len(v["version"])==2 and
            all(type(x)is int and 0<x<1<<63 for x in v["version"])),"exact successful Watcher token")
    else:
        require(v["version"]is None and (v["family"]==1 and 1<=v["code"]<=4095 or
            v["family"]==2 and 1<=v["code"]<=8),"exact original OS/literal error")
    return v
