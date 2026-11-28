#!/usr/bin/env python3
"""Execute each frozen original JSON value command once and retain full object observations."""
import argparse,gzip,hashlib,json,os,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,require,pin,sha,source_evidence
import cases
from observation import observe,describe,constructed
from runtime import verify_runtime
UNSET=object()
def main():
    p=argparse.ArgumentParser();p.add_argument("--group",required=True);p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args();identity=source_evidence(ROOT)
    runtime=verify_runtime(a.runtime);require(not a.output.exists(),"fresh actual original value capture");a.output.mkdir(parents=True)
    rows=[];whole=hashlib.sha256();offset=0;success=False
    raw=(a.output/"records.bin.gz").open("xb");stream=gzip.GzipFile(filename="",mode="wb",fileobj=raw,compresslevel=1,mtime=0)
    try:
        for case in cases.cases(int(a.group)):
            wire=case["wire"];command=case["command"];left=right=UNSET
            before_left=before_right=b"";counts=dict(loads=0,dumps=0,subscript=0,get=0,update=0,equality=0)
            try:
                if "constructed"in case:left,right=constructed(case)
                else:
                    counts["loads"]+=1;left=json.loads(b"\xff\xfe\0\0"+case["primary"].encode("utf-32-le","surrogatepass"))
                    if command in(4,5):
                        counts["loads"]+=1;right=json.loads(b"\xff\xfe\0\0"+case["auxiliary"].encode("utf-32-le","surrogatepass"))
                before_left=observe(left)
                if right is not UNSET:before_right=observe(right)
                if command==1:result=left
                elif command==2:counts["subscript"]+=1;result=left[case["auxiliary"]]
                elif command==3:counts["dumps"]+=1;result=json.dumps(left,sort_keys=True)
                elif command==4:
                    counts["update"]+=1;left.update(right)
                    counts["dumps"]+=1;result=json.dumps(left,sort_keys=True)
                elif command==5:counts["equality"]+=1;result=left==right
                else:counts["get"]+=1;result=left.get(case["auxiliary"])
                info,payload=describe(result)
                if command in(3,4):
                    require(type(result)is str,"actual dumps result");payload=result.encode("ascii")
                elif command==5:payload=b"1"if result else b"0"
                elif info["tag"]>=6:payload=observe(result)
                meta=dict(status="RETURNED",exception_class=None,message=None,**info)
            except Exception as error:
                payload=(type(error).__name__+": "+str(error)).encode("utf-8")
                meta=dict(status="RAISED",exception_class=type(error).__name__,message=str(error))
            after_left=observe(left)if left is not UNSET else b""
            after_right=observe(right)if right is not UNSET else b""
            meta["operations"]=counts
            meta["left_truth"]=bool(left)if left is not UNSET else None
            meta["right_truth"]=bool(right)if right is not UNSET else None
            metadata=canonical(meta)
            header=struct.pack("<10Q",case["case_id"],len(wire),len(payload),len(metadata),len(rows)+1,
                len(before_left),len(before_right),len(after_left),len(after_right),0)
            digest=hashlib.sha256();size=0
            for span in(header,wire,payload,metadata,before_left,before_right,after_left,after_right):
                stream.write(span);digest.update(span);whole.update(span);size+=len(span)
            rows.append(dict(case_id=case["case_id"],label=case["label"],offset=offset,bytes=size,
                input_bytes=len(wire),input_sha256=sha(wire),payload_bytes=len(payload),payload_sha256=sha(payload),
                metadata=meta,observed_before=[sha(before_left),sha(before_right)],observed_after=[sha(after_left),sha(after_right)],
                record_sha256=digest.hexdigest()))
            offset+=size
        success=True
    finally:
        stream.close();raw.close();require(verify_runtime(a.runtime)==runtime,"whole actual interpreter unchanged")
        (a.output/"records.json").write_bytes(canonical(rows))
        result=dict(schema="hepta.runtime.python-json-value.original.v2",status="PASS"if success else"FAIL",
            group=a.group,cases=len(rows),raw=dict(bytes=offset,sha256=whole.hexdigest()),compressed=pin(a.output/"records.bin.gz"),
            records=pin(a.output/"records.json"),source=identity,runtime=runtime,pid=os.getpid(),python=sys.executable,
            complete_actual_operands=True,application_replay=False)
        require(source_evidence(ROOT)==identity,"source unchanged during original capture")
        (a.output/"CAPTURE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
