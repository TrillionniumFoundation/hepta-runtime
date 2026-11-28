#!/usr/bin/env python3
"""Physical negative copies and two full relocations; no original or native application execution."""
from pathlib import Path
import argparse,copy,gzip,hashlib,os,shutil,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import decode,encoded,pin,require,source_evidence
from process import Recorder
def clone(source,target):
    require(not target.exists(),"fresh retained physical control copy")
    shutil.copytree(source,target,copy_function=os.link)
def replace(path,raw):
    temporary=path.with_name(path.name+".new");require(not temporary.exists(),"fresh mutation")
    temporary.write_bytes(raw);temporary.chmod(path.stat().st_mode&0o777);os.replace(temporary,path)
def case_read(data):
    report=decode((data/"native/CAPTURE.json").read_bytes())
    with gzip.open(data/"native/cases.jsonl.gz","rb")as stream:
        lines=stream.readlines()
    require(len(lines)==1,"one fixed actual control case");return decode(lines[0]),report
def case_write(data,case,report):
    raw=encoded(case);replace(data/"native/cases.jsonl.gz",gzip.compress(raw,compresslevel=1,mtime=0))
    report["case_rows"]=[dict(id=case["input"]["id"],bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())]
    report["cases_file"]=pin(data/"native/cases.jsonl.gz");report["cases_raw"]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    replace(data/"native/CAPTURE.json",encoded(report))
def mutate(kind,source,data):
    case,report=case_read(data);carrier=data/"native"/case["process_path"]
    if kind=="result-fields":
        case["actual"]["chain"]["invocations"][0]["result"]["ok"]=False
    elif kind=="actual-context":
        case["actual"]["chain"]["invocations"][0]["snapshots"]["context"]["observed_context"]["address"]+=4096
    elif kind=="eof-descriptor":
        case["actual"]["hooks"]["eof"][0]["fds"]["99999"]=dict(target="unobserved",error={"type":"OSError","errno":5})
    elif kind=="kernel-stat-bytes":
        path=carrier/"kernel.jsonl.gz";records=[decode(line)for line in gzip.decompress(path.read_bytes()).splitlines()]
        scopes={r["scope"]for r in records if r["record"]=="MARK"and r["application"]}
        target=next(r for r in records if r["record"]=="LEAVE"and r["scope"]in scopes and r["number"]==5 and r["result"]==0)
        span=next(r for r in target["output"]if r["label"]=="stat");raw=bytearray.fromhex(span["hex"]);raw[48]^=1;span["hex"]=raw.hex()
        raw=b"".join(encoded(r)for r in records);replace(path,gzip.compress(raw,compresslevel=1,mtime=0))
        receipt=decode((carrier/"carrier-process.json").read_bytes())
        receipt["kernel"]["raw"]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest());receipt["kernel"]["compressed"]=pin(path)
        replace(carrier/"carrier-process.json",encoded(receipt));case["process"]=receipt
        report["processes"][0]["receipt"]=pin(carrier/"carrier-process.json")
    elif kind=="stdout-truncated":
        path=carrier/"carrier.stdout.gz";raw=gzip.decompress(path.read_bytes());replace(path,gzip.compress(raw[:-1],compresslevel=1,mtime=0))
        receipt=decode((carrier/"carrier-process.json").read_bytes())
        receipt["stdout"]["raw"]=dict(bytes=len(raw)-1,sha256=hashlib.sha256(raw[:-1]).hexdigest())
        receipt["stdout"]["compressed"]=pin(path);replace(carrier/"carrier-process.json",encoded(receipt));case["process"]=receipt
        report["processes"][0]["receipt"]=pin(carrier/"carrier-process.json")
    elif kind=="source-bytes":
        path=source/"trusted-build/native/binary_write_body.hepta";replace(path,path.read_bytes()+b"\n")
    elif kind=="unread-buffer":
        raw=b"frozen-unreferenced-complete-buffer";key=hashlib.sha256(raw).hexdigest()
        path=data/"native/buffers"/(key+".gz");require(not path.exists(),"new unread physical buffer")
        path.write_bytes(gzip.compress(raw,compresslevel=1,mtime=0));report["buffers"]["blocks"]+=1
    elif kind=="kernel-tail":
        path=carrier/"kernel.jsonl.gz";raw=path.read_bytes();replace(path,raw[:-8])
    else:raise ValueError("unknown frozen physical mutation")
    case_write(data,case,report)
def read(source,data,runtime,expected):
    from read_capture import verify
    from readonly import guarded
    runtime_path=runtime/"RUNTIME.json";runtime_value=decode(runtime_path.read_bytes())
    def operation():
        try:
            source_evidence(source)
            value=verify(source,data,0,runtime_value)
        except(ValueError,EOFError,OSError)as e:
            require(expected=="refuse","unmodified relocated evidence refused: "+str(e))
            return dict(status="REFUSED",error_type=type(e).__name__,message=str(e))
        require(expected=="admit","mutated physical evidence unexpectedly admitted")
        return dict(status="ADMITTED",result=value)
    return guarded(operation,roots=[source,data,runtime])
def run(source,data,runtime,output):
    output.mkdir(parents=True);rec=Recorder(source,output/"processes");rows=[]
    controls=("result-fields","actual-context","eof-descriptor","kernel-stat-bytes","stdout-truncated","source-bytes","unread-buffer","kernel-tail")
    for label in(*controls,"relocation-one","relocation-two"):
        root=output/label;root.mkdir();clone(source,root/"source");clone(data,root/"data");clone(runtime,root/"runtime")
        expected="refuse"if label in controls else"admit"
        if expected=="refuse":mutate(label,root/"source",root/"data")
        raw,process=rec.run(label,[sys.executable,"-I","-S","-B",Path(__file__).resolve(),"read",
            "--source",root/"source","--data",root/"data","--runtime",root/"runtime","--expected",expected],timeout=180)
        result=decode(raw);require(result["status"]=="READONLY_PASS"and result["before"]==result["after"]and len(result["probes"])==11,
            "full physical source/evidence custody")
        expected_status="REFUSED"if expected=="refuse"else"ADMITTED";require(result["evidence"]["status"]==expected_status,"physical outcome")
        rows.append(dict(name=label,expected=expected_status,process=process,result=result))
    result=dict(status="PHYSICAL_CONTROLS_PASS",refusals=len(controls),admissions=2,controls=rows,
        source_evidence=source_evidence(source),application_calls=0,control_replays=0,all_variants_retained=True)
    (output/"CONTROLS.json").write_bytes(encoded(result));return result
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["run","read"]);p.add_argument("--source",type=Path,required=True)
    p.add_argument("--data",type=Path,required=True);p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--output",type=Path);p.add_argument("--expected",choices=["refuse","admit"]);a=p.parse_args()
    if a.stage=="run":result=run(a.source.resolve(strict=True),a.data.resolve(strict=True),a.runtime.resolve(strict=True),a.output.absolute())
    else:result=read(a.source.resolve(strict=True),a.data.resolve(strict=True),a.runtime.resolve(strict=True),a.expected)
    print(encoded(result).decode(),end="")
