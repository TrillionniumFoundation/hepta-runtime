"""Pure complete-buffer and JSON transport equivalence; never executes HIA or Rust."""
from pathlib import Path
import argparse,ast,gzip,hashlib,io,math,os,struct,sys,time,types
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded as previous,loads,read,pin,require,source,files
from evidence_codec import encoded
KEYS={"index","kind","offset","case","step","operation","meta","buffers"}
def record_method(path,encoder):
    tree=ast.parse(read(path));cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=="Capture")
    f=next(n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name=="record")
    module=ast.Module(body=[f],type_ignores=[]);scope=dict(encoded=encoder,pin=pin,struct=struct)
    exec(compile(ast.fix_missing_locations(module),str(path),"exec"),scope)
    return scope["record"]
def instance(method,stream):
    value=types.SimpleNamespace(rows=[],offset=8,case=0,step=0,operation="transport-proof",stream=stream)
    value.record=types.MethodType(method,value);return value
def take(stream,size):
    raw=stream.read(size);require(len(raw)==size,"complete exact physical frame");return raw
def frames(path,encoder):
    with gzip.open(path,"rb")as s:
        require(take(s,8)==b"HNWLOG01","original complete buffer stream magic")
        offset=8;index=0
        while True:
            prefix=take(s,8)
            if prefix==b"HNWEND01":
                require(struct.unpack("<Q",take(s,8))[0]==index and s.read(1)==b"","complete footer, EOF and gzip checksum")
                return
            n=struct.unpack("<Q",prefix)[0];require(0<n<=16*1024*1024,"complete bounded record header")
            header=take(s,n);row=loads(header)
            require(set(row)==KEYS and row["index"]==index and row["offset"]==offset and
                header==encoder(row) and type(row["buffers"])is list and len(row["buffers"])<=1024,
                "complete canonical metadata, count and physical position")
            raws=[]
            for expected in row["buffers"]:
                require(set(expected)=={"bytes","sha256"}and type(expected["bytes"])is int and
                    0<=expected["bytes"]<=2*1024*1024,"full native buffer bounds")
                raw=take(s,expected["bytes"]);require(pin(raw)==expected,"every entire native buffer hash");raws.append(raw)
            yield row,tuple(raws)
            index+=1;offset+=8+n+sum(map(len,raws))
def compare(old,new):
    a=frames(old,previous);b=frames(new,encoded);count=total=0
    sentinel=object()
    while True:
        x=next(a,sentinel);y=next(b,sentinel)
        require((x is sentinel)==(y is sentinel),"same complete native record domain")
        if x is sentinel:break
        r,raws=x;s,data=y
        require(dict(r,offset=0)==dict(s,offset=0)and raws==data,
            "all complete original metadata and every ordered physical native byte unchanged")
        count+=1;total+=sum(map(len,raws))
    return dict(records=count,complete_buffer_bytes=total,ordered_full_bytes_equal=True)
def rewrite(old,output,method):
    output.mkdir(parents=True,exist_ok=False);out=output/"complete-native-buffers.bin.gz"
    with out.open("xb")as physical:
        with gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=physical,mtime=0)as stream:
            stream.write(b"HNWLOG01");writer=instance(method,stream);old_rows=[]
            for row,raws in frames(old,previous):
                writer.case=row["case"];writer.step=row["step"];writer.operation=row["operation"]
                writer.record(row["kind"],raws,row["meta"]);old_rows.append(row)
            stream.write(b"HNWEND01"+struct.pack("<Q",len(writer.rows)))
    require(old_rows==loads(read(old.parent/"RECORDS.json")),"whole original record index without missing rows")
    (output/"RECORDS.json").write_bytes(encoded(writer.rows))
    require(loads(read(output/"RECORDS.json"))==writer.rows,"entire new physical record index")
    result=compare(old,out)
    return dict(result,input=pin(read(old)),output=pin(read(out)),index=pin(read(output/"RECORDS.json")))
class Sink:
    def __init__(self,cut=None):self.parts=[];self.cut=cut
    def write(self,raw):
        if self.cut is not None:
            self.parts.append(raw[:self.cut]);raise OSError(28,"owned partial evidence sink")
        self.parts.append(bytes(raw));return len(raw)
def controls(method,old_method):
    values=[None,True,False,0,-1,(1<<64)-1,1<<256,-0.0,1.25,
        {"unicode":"é\\\"\n\u0000","surrogate":"\ud800","empty":[],"null":None,"integer":(1<<64)-1},
        [[],{},["a",0,True,None]],{"z":[{"x":list(range(17))}],"a":{str(i):i for i in range(40)}}]
    rows=[]
    for i,value in enumerate(values):
        old=previous(value);new=encoded(value)
        require(loads(new)==loads(old)and previous(loads(new))==old,"complete JSON inverse including all integer bits")
        rows.append(dict(name="json-"+str(i),old=pin(old),new=pin(new),inverse=pin(previous(loads(new)))))
    for i,value in enumerate((float("nan"),float("inf"),-float("inf"))):
        errors=[]
        for fn in(previous,encoded):
            try:fn(value)
            except ValueError:errors.append(True)
        require(errors==[True,True],"same non-finite rejection");rows.append(dict(name="nonfinite-"+str(i),rejected=True))
    old_sink=Sink();new_sink=Sink();a=instance(old_method,old_sink);b=instance(method,new_sink)
    samples=[(),(b"",),(bytes(range(256))*513,),tuple(bytes([i%256])*4096 for i in range(260)),
        (b"\0"*131088,b"\xa5"*144,b"\x5a"*16),(b"prefix\0\xffsuffix",b"",b"\xff"*65552)]
    for i,raws in enumerate(samples):
        meta=dict(index=i,nested=values[-3:],unsigned=(1<<64)-1)
        a.case=b.case=i;a.step=b.step=2*i
        oa=len(old_sink.parts);nb=len(new_sink.parts)
        a.record("actual-record-method",raws,meta);b.record("actual-record-method",raws,meta)
        x=a.rows[-1];y=b.rows[-1]
        require(dict(x,offset=0)==dict(y,offset=0),"all synthetic record fields preserved")
        physical=b"".join(new_sink.parts[nb:]);n=struct.unpack("<Q",physical[:8])[0]
        require(loads(physical[8:8+n])==y and physical[8+n:]==b"".join(raws),"every complete synthetic payload")
        rebuilt=struct.pack("<Q",len(previous(x)))+previous(x)+physical[8+n:]
        require(rebuilt==b"".join(old_sink.parts[oa:])and len(new_sink.parts)-nb==1,
            "actual old record reconstructed byte for byte and one complete new sink write")
        rows.append(dict(name="record-"+str(i),buffers=len(raws),complete_bytes=sum(map(len,raws)),
            old_frame=pin(rebuilt),new_frame=pin(physical)))
    for cut in(0,1,17,4096):
        for label,fn in(("old",old_method),("new",method)):
            sink=Sink(cut);writer=instance(fn,sink);caught=False
            try:writer.record("partial",(b"\x7f"*8192,),dict(cut=cut))
            except OSError as error:caught=error.errno==28
            require(caught and writer.rows==[],"partial sink cannot accept a record or produce success")
            rows.append(dict(name=label+"-partial-"+str(cut),rejected=True,partial=pin(b"".join(sink.parts))))
    return rows
def run(prior,output):
    identity=source();started=time.monotonic();output.mkdir(parents=True,exist_ok=False)
    require(pin(read(prior/"source/SOURCE.json"))==dict(bytes=9359,
        sha256="226fad27b465d2fdf516e2b19c6bc7387813e5b3abb7420ec3d8d5d832eefb1d"),"exact preserved V2 failure source")
    method=record_method(ROOT/"capture_native.py",encoded)
    old_method=record_method(ROOT/"baseline/capture_native.py.txt",previous)
    ordinary=controls(method,old_method);(output/"CONTROLS.json").write_bytes(previous(ordinary))
    streams=[];jsons=[]
    groups=("ordinary","lru","wide-128","wide-258")
    for group in groups:
        base=prior/"run"/("paired-"+group)
        for role in("native-observed","native-off"):
            old=base/"roles"/role/"capture/complete-native-buffers.bin.gz"
            row=rewrite(old,output/"buffers"/group/role,method)
            streams.append(dict(group=group,role=role,**row))
        for relative in("INITIALS.json","OBSERVATIONS.json","RETIREMENT.json","PROCESSES.json","TRACE-CUSTODY.json",
            "roles/native-observed/EXCHANGES.json","roles/native-off/EXCHANGES.json","roles/original/EXCHANGES.json"):
            path=base/relative
            if not path.exists():
                require(group=="wide-258","only the known incomplete parent failure has missing final JSON");continue
            raw=read(path);value=loads(raw);require(previous(value)==raw,"entire original canonical evidence JSON")
            rewritten=encoded(value);require(previous(loads(rewritten))==raw,"complete actual JSON inverse with no field omission")
            destination=output/"json"/group/relative;destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(rewritten);require(previous(loads(read(destination)))==raw,"actual complete retained JSON readback")
            jsons.append(dict(group=group,path=relative,old=pin(raw),new=pin(rewritten)))
    require(len(streams)==8 and len(ordinary)==29 and len(jsons)==24,"all exact former completed streams and controls")
    original=loads(read(prior.parent/"artifact-manifest.json"))
    require(files(prior)=={n:{k:r[k]for k in("bytes","sha256","mode")}for n,r in original["files"].items()},
        "every retained original failure byte and mode unchanged after the pure proof")
    require(source()==identity,"complete source unchanged by proof")
    report=dict(status="COMPLETE_EVIDENCE_TRANSPORT_INVERSE_PASS",source_manifest_sha256=identity,
        elapsed_seconds=time.monotonic()-started,timeout_seconds=180,controls=ordinary,streams=streams,json=jsons,
        records=sum(r["records"]for r in streams),complete_buffer_bytes=sum(r["complete_buffer_bytes"]for r in streams),
        native_executions=0,rust_executions=0,application_streams_modified=False,
        original_v1_and_v2_failures_preserved=True,namespace_version_qualified=False,public_handler_qualified=False)
    require(report["elapsed_seconds"]<=180,"unchanged pure-reader proof deadline")
    (output/"PROOF.json").write_bytes(previous(report));print(previous(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--prior",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.prior.resolve(strict=True),a.output.absolute())
