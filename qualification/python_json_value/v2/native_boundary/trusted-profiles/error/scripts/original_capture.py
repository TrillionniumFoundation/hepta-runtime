#!/usr/bin/env python3
"""One actual original operation per frozen depth input; full input and outcome custody."""
import argparse,gzip,hashlib,os,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require,sha,source_evidence
from runtime import verify_runtime
import cases,operations
def observe(value):
    shape=bytearray()
    while type(value)in(list,dict)and len(value):
        require(len(value)==1,"one child in complete observed profile tree")
        if type(value)is list:shape.append(1);value=value[0]
        else:
            require(list(value)==["x"],"complete observed dictionary key")
            shape.append(2);value=value["x"]
    kind=type(value).__name__
    if kind=="float":data=struct.pack("<d",value).hex()
    elif kind=="str":data=value.encode("utf-32-le","surrogatepass").hex()
    elif kind=="int":data=str(value)
    elif kind=="bool":data="true"if value else"false"
    elif kind=="NoneType":data=None
    else:require(type(value)in(list,dict)and not value,"complete terminal observed value");data=[]
    return struct.pack("<Q",len(shape))+shape+canonical(dict(type=kind,data=data))
def identities(left,right):
    result=bytearray()
    while True:
        result.append(int(left is right))
        if type(left)is list and len(left)==1 and type(right)is list and len(right)==1:
            left,right=left[0],right[0]
        elif type(left)is dict and list(left)==["x"]and type(right)is dict and list(right)==["x"]:
            left,right=left["x"],right["x"]
        else:break
    return bytes(result)

def describe(value):
    kind=type(value).__name__;truth=bool(value)
    if value is None:payload=b""
    elif type(value)is bool:payload=b"1"if value else b"0"
    elif type(value)is float:payload=struct.pack("<d",value)
    elif type(value)is int:payload=str(value).encode()
    elif type(value)is str:payload=value.encode("utf-32-le","surrogatepass")
    else:payload=observe(value)
    return dict(type=kind,truth=truth,length=len(value)if type(value)in(str,list,dict)else None),payload
def main():
    p=argparse.ArgumentParser();p.add_argument("--group",required=True);p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args();identity=source_evidence(ROOT)
    runtime=verify_runtime(a.runtime);require(not a.output.exists(),"fresh original depth capture");a.output.mkdir(parents=True)
    raw=(a.output/"records.bin.gz").open("xb");stream=gzip.GzipFile(filename="",mode="wb",fileobj=raw,compresslevel=1,mtime=0)
    rows=[];whole=hashlib.sha256();offset=0;success=False
    try:
        for case in cases.cases(a.group):
            primary=cases.text(case["shape"],case["depth"],case["leaf"]);wire=primary.encode("utf-32-le","surrogatepass")
            left=right=None
            if case["mode"]!="parse":
                left=cases.constructed(case["shape"],case["depth"],case["leaf"])
                if case["mode"]=="equal":right=cases.constructed(case["shape"],case["depth"],case["leaf"])
            before_left=observe(left)if case["mode"]!="parse"else b""
            before_right=observe(right)if case["mode"]=="equal"else b""
            identity_before=identities(left,right)if case["mode"]=="equal"else b""
            try:
                if case["mode"]=="parse":value=operations.parse(primary)
                elif case["mode"]=="dump":value=operations.dump(left)
                else:value=operations.equal(left,right)
            except Exception as error:
                payload=(type(error).__name__+": "+str(error)).encode("utf-8")
                meta=dict(status="RAISED",exception_class=type(error).__name__,message=str(error))
            else:
                meta,payload=describe(value);meta.update(status="RETURNED",exception_class=None,message=None)
            after_left=observe(left)if case["mode"]!="parse"else b""
            after_right=observe(right)if case["mode"]=="equal"else b""
            identity_after=identities(left,right)if case["mode"]=="equal"else b""
            meta.update(identity_before=identity_before.hex(),identity_after=identity_after.hex())
            metadata=canonical(meta);head=struct.pack("<10Q",case["case_id"],len(wire),len(payload),len(metadata),len(rows)+1,
                len(before_left),len(before_right),len(after_left),len(after_right),0)
            digest=hashlib.sha256();size=0
            for span in(head,wire,payload,metadata,before_left,before_right,after_left,after_right):stream.write(span);digest.update(span);whole.update(span);size+=len(span)
            rows.append(dict(**case,offset=offset,bytes=size,input_bytes=len(wire),input_sha256=sha(wire),
                payload_bytes=len(payload),payload_sha256=sha(payload),metadata=meta,
                observed_before=[sha(before_left),sha(before_right)],observed_after=[sha(after_left),sha(after_right)],
                record_sha256=digest.hexdigest()))
            offset+=size
        success=True
    finally:
        stream.close();raw.close();require(verify_runtime(a.runtime)==runtime,"complete actual interpreter stable")
        (a.output/"records.json").write_bytes(canonical(rows))
        result=dict(schema="hepta.runtime.python-json-value.original-depth-capture.v1",status="PASS"if success else"FAIL",
            source=identity,group=a.group,cases=len(rows),pid=os.getpid(),python=sys.executable,runtime=runtime,
            raw=dict(bytes=offset,sha256=whole.hexdigest()),compressed=pin(a.output/"records.bin.gz"),records=pin(a.output/"records.json"),
            native_applications=0,application_replays=0)
        require(source_evidence(ROOT)==identity,"profile source unchanged")
        (a.output/"CAPTURE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
