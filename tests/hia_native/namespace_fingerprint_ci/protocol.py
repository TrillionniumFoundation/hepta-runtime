"""Fixed shared-filesystem corpus and bounded line framing, no implementation oracle."""
import json
from common import ROOT,loads,read,require
def domain(root=ROOT):
    value=loads(read(root/"DOMAIN.json"))
    require(value["schema"]=="hepta.namespace-fingerprint.domain.v1" and value["same_physical_tree"] is True,"exact corpus schema")
    require(len(value["cases"])==value["total_cases"]==72 and sum(len(r["steps"]) for r in value["cases"])==value["total_operations"]==156,"all frozen cases and operations")
    require([r["case"] for r in value["cases"]]==list(range(72)),"complete ordered unique cases")
    require(value["groups"]==list(dict.fromkeys(r["group"] for r in value["cases"])),"fixed process groups")
    return value
def cases(group,root=ROOT):
    d=domain(root);require(group in d["groups"],"known complete group")
    return [r for r in d["cases"] if r["group"]==group]
def line(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
def require_semantic(value):
    require(type(value)is dict and set(value)=={"kind","errno","digest"},"complete semantic result")
    require(type(value["kind"])is int and value["kind"] in(0,1) and type(value["errno"])is int and 0<=value["errno"]<=4095,"exact result integers")
    require(type(value["digest"])is str and len(value["digest"])==64 and bytes.fromhex(value["digest"]).hex()==value["digest"],"complete digest bytes")
    if value["kind"]==0:require(value["errno"]==0,"no error with digest")
    else:require(value["digest"]=="00"*32,"no digest with original error")
    return value
