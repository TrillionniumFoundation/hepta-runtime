"""Read the entire completed uploaded capture; print bounded structural diagnostics only."""
import argparse,gzip,hashlib,json,re,struct,sys
from pathlib import Path
def require(value,message):
    if not value:raise ValueError(message)
def enc(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path):return Path(path).read_bytes()
def load(path):return json.loads(read(path))
def take(stream,size):
    out=bytearray()
    while len(out)<size:
        part=stream.read(size-len(out));require(part,"whole record");out+=part
    return bytes(out)
def word(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def trace(path):
    raw=read(path);lines=raw.decode("utf-8").splitlines();counts={};samples={}
    for i,line in enumerate(lines):
        match=re.match(r"\d+\s+(\w+)\(",line)
        if match:
            name=match[1];counts[name]=counts.get(name,0)+1
            if name not in samples:samples[name]=lines[i:i+3]
            if name=="read" and re.search(r"read\(0x[2-9a-f][0-9a-f],",line) and re.search(r"=\s+0x[1-9a-f]",line):
                samples.setdefault("actual_event_read",lines[i:i+8])
    return dict(identity=pin(raw),lines=len(lines),calls=counts,samples=samples,head=lines[:24],tail=lines[-8:])
def native(folder):
    rows=load(folder/"RECORDS.json");counts={};samples={};total=0;offset=8
    with gzip.open(folder/"complete-native-buffers.bin.gz","rb")as f:
        require(take(f,8)==b"HNWLOG01","full header")
        for index,row in enumerate(rows):
            require(row["index"]==index and row["offset"]==offset,"full ordered index")
            n=word(take(f,8),0);header=take(f,n)
            require(json.loads(header)==row,"physical record metadata")
            offset+=8+n;buffers=[]
            for p in row["buffers"]:
                raw=take(f,p["bytes"]);require(pin(raw)==p,"all complete physical buffer bytes")
                buffers.append(raw);offset+=len(raw);total+=len(raw)
            kind=row["kind"];counts[kind]=counts.get(kind,0)+1
            if kind not in samples:
                sample=dict(row=row)
                if kind=="checkpoint":
                    sample["row"]=dict(row,meta={k:v for k,v in row["meta"].items()if k not in("state","roots","pins")})
                    sample["checkpoint_state_keys"]=sorted(row["meta"]["state"])
                    sample["checkpoint_roots_count"]=len(row["meta"]["roots"]);sample["checkpoint_pins_count"]=len(row["meta"]["pins"])
                if kind=="observation":
                    ctx=buffers[0];event=ctx[24960:25088]
                    sample.update(context_words=[word(ctx,i)for i in range(0,256,8)],
                        workspace_words=[word(ctx,32768+i)for i in range(0,512,8)],
                        input_hex=ctx[8192:8192+min(word(ctx,112),256)].hex(),
                        output_hex=ctx[24704:24832].hex(),event_words=[word(event,i)for i in range(8,128,8)])
                elif kind in("entry","private-owner"):
                    sample.update(input_hex=buffers[0][:256].hex(),output_hex=buffers[4][:128].hex())
                samples[kind]=sample
        require(take(f,16)==b"HNWEND01"+struct.pack("<Q",len(rows))and f.read()==b"","closed complete stream")
    return dict(report=load(folder/"NATIVE.json"),records=len(rows),full_buffer_bytes=total,counts=counts,samples=samples)
def run(root,output):
    root=root.resolve(strict=True);capture=root/"run";m=load(capture/"CAPTURE.json")
    d=load(root/"source/DOMAIN.json");groups={}
    for group in d["groups"]:
        p=capture/("paired-"+group)
        report=load(p/"PAIRED.json");initial=load(p/"INITIALS.json");observed=load(p/"OBSERVATIONS.json")
        roles={}
        for role in("native-observed","native-off","original"):
            r=p/"roles"/role
            values=[json.loads(line)for line in read(r/"stdout").splitlines()]
            role_data=dict(process=load(r/"PROCESS.json"),trace=trace(r/"syscalls.strace"),
                ready=values[0],reply_count=len(values)-1,first_reply=values[1]if group=="ordinary"else dict(keys=sorted(values[1]),state_keys=sorted(values[1].get("state",{}))),last_reply=values[-1])
            if role!="original":role_data["native"]=native(r/"capture")
            roles[role]=role_data
        groups[group]=dict(report=report,roles=roles,initial=initial[0]if group=="ordinary"else dict(cases=len(initial),keys=sorted(initial[0])),
            first_observation=observed[0]if group=="ordinary"else dict(keys=sorted(observed[0])),
            retirement=load(p/"RETIREMENT.json")[-1]if group=="ordinary"else dict(cases=len(initial)),custody=load(p/"TRACE-CUSTODY.json"))
    result=dict(status="COMPLETE_UPLOADED_CAPTURE_INSPECTED",capture={k:v for k,v in m.items()if k!="files"},
        process_records=load(capture/"processes/processes.json"),groups=groups,
        full_semantic_reader_pending=True,application_executions=0,native_executions=0,rust_executions=0)
    output.write_bytes(enc(result))
    print("WATCHER_CAPTURE_INSPECTION_BEGIN")
    print(enc(result).decode(),end="")
    print("WATCHER_CAPTURE_INSPECTION_END")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.root,a.output)
