"""Read the entire actual failed archive and complete trace/buffer prefix; no replay."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,struct,sys,time,traceback
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from restore import run as restore,read,loads,pin,require,enc
def stream_take(s,n):
    raw=bytearray()
    while len(raw)<n:
        part=s.read(n-len(raw))
        if not part:break
        raw+=part
    return bytes(raw)
def inspect(root):
    allfiles={}
    for folder,dirs,names in os.walk(root):
        for n in names:
            path=Path(folder)/n;allfiles[path.relative_to(root).as_posix()]=pin(read(path))
    m=loads(read(root/"run/CAPTURE.json"));processes=loads(read(root/"run/processes/processes.json"))
    require(m["status"]=="FAIL"and processes[-1]["name"]=="paired-wide-258"and
        processes[-1]["timed_out"]is True and processes[-1]["timeout_seconds"]==60,"precise unchanged deadline failure")
    report=dict(status="COMPLETE_FAILED_WATCHER_CAPTURE_INSPECTED",files=len(allfiles),
        bytes=sum(x["bytes"]for x in allfiles.values()),source_manifest=pin(read(root/"source/SOURCE.json")),
        processes=processes,groups=[],native_executions=0,rust_executions=0)
    for group in loads(read(root/"source/DOMAIN.json"))["groups"]:
        folder=root/"run"/("paired-"+group)
        if not folder.exists():continue
        row=dict(group=group)
        paired=folder/"PAIRED.json"
        if paired.is_file():row["paired"]=loads(read(paired))
        for name in("FAILURE.json","PROCESSES.json"):
            if(folder/name).is_file():row[name]=loads(read(folder/name))
        roles={}
        for role in("native-observed","native-off","original"):
            part=folder/"roles"/role
            if not part.exists():continue
            data={}
            if (part/"syscalls.strace").is_file():
                raw_trace=read(part/"syscalls.strace");trace_lines=raw_trace.decode().splitlines()
                import re
                counts={}
                for line in trace_lines:
                    mcall=re.match(r"^([0-9]+)\s+([A-Za-z0-9_]+)\(",line)
                    if mcall:
                        key=mcall[1]+":"+mcall[2];counts[key]=counts.get(key,0)+1
                data["trace"]=dict(**pin(raw_trace),lines=len(trace_lines),syscalls=counts,
                    first=trace_lines[:6],last=trace_lines[-8:],read_payload_format=[v for v in trace_lines if " | "in v][:30])
            for name in("stdin","stdout","stderr"):
                raw=read(part/name);data[name]=pin(raw)
                if name!="stderr":
                    lines=raw.split(b"\n");complete=[];bad=[]
                    for i,line in enumerate(lines[:-1]):
                        try:
                            v=loads(line);result={k:v[k]for k in("cmd","command","case","step","operation","role")if k in v}
                            if isinstance(result.get("operation"),dict):result["operation"]=result["operation"]["op"]
                            if"state"in v:result["state_counts"]=dict(watchers=len(v["state"]["watchers"]),
                                roots=len(v["state"]["roots"]),counts=[len(w["state"]["watches"])for w in v["state"]["watchers"]])
                            complete.append(result)
                        except Exception as e:bad.append(dict(line=i,error=repr(e)))
                    data[name].update(complete_lines=len(complete),last_rows=complete[-6:],bad_lines=bad,
                        partial_tail=pin(lines[-1]))
                else:
                    markers=[]
                    for at in range(0,len(raw)//24*24,24):
                        chunk=raw[at:at+24];markers.append(dict(tag=chunk[:8].decode("ascii","backslashreplace"),
                            case=struct.unpack_from("<Q",chunk,8)[0],step=struct.unpack_from("<Q",chunk,16)[0]))
                    data[name].update(last_markers=markers[-6:],partial=pin(raw[len(raw)//24*24:]))
            capture=part/"capture"
            for n in("NATIVE.json","OBSERVER-ERRORS.json"):
                if(capture/n).is_file():data[n]=loads(read(capture/n))
            full=capture/"complete-native-buffers.bin.gz"
            if full.is_file():
                stats=dict(records=0,bytes=0,steps={},kind={},last_rows=[],owner_intervals=[],complete_footer=False)
                pending=None;start=None;last=None;failure=None
                try:
                    with full.open("rb")as physical,gzip.GzipFile(fileobj=physical,mode="rb")as s:
                        require(stream_take(s,8)==b"HNWLOG01","actual captured stream magic")
                        while True:
                            prefix=stream_take(s,8)
                            if prefix==b"HNWEND01":
                                require(struct.unpack("<Q",stream_take(s,8))[0]==stats["records"]and s.read()==b"","complete end")
                                stats["complete_footer"]=True;break
                            require(len(prefix)==8,"complete next record length")
                            size=struct.unpack("<Q",prefix)[0];require(size<=1<<20,"bounded actual record header")
                            header=stream_take(s,size);require(len(header)==size,"complete record header");r=loads(header)
                            require(r["index"]==stats["records"],"complete prefix record order")
                            raws=[]
                            for p in r["buffers"]:
                                b=stream_take(s,p["bytes"]);require(pin(b)==p,"every complete prefix physical buffer")
                                raws.append(b)
                            stats["records"]+=1;stats["bytes"]+=sum(len(b)for b in raws)
                            kind=r["kind"];stats["kind"][kind]=stats["kind"].get(kind,0)+1
                            key=str(r["case"])+":"+str(r["step"]);step=stats["steps"].setdefault(key,dict(records=0,kinds={}))
                            step["records"]+=1;step["kinds"][kind]=step["kinds"].get(kind,0)+1
                            item={k:r[k]for k in("index","case","step","kind","operation")}
                            if kind=="observation":
                                ev=bytes.fromhex(r["meta"]["event"]);ns=r["meta"]["observed_ns"]
                                if start is None:start=ns
                                last=ns;step.setdefault("first_observed_ns",ns);step["last_observed_ns"]=ns
                                item.update(magic=ev[:8].decode(),phase=struct.unpack_from("<Q",ev,8)[0],
                                    generation=struct.unpack_from("<Q",ev,24)[0],sequence=struct.unpack_from("<Q",ev,40)[0])
                                if ev[:8]==b"HNWOWN01":
                                    if item["phase"]==0:pending=(ns,r["case"],r["step"])
                                    elif pending is not None:
                                        stats["owner_intervals"].append(dict(case=pending[1],step=pending[2],ns=ns-pending[0]))
                                        step["owner_intervals"]=step.get("owner_intervals",0)+1
                                        step["owner_interval_ns"]=step.get("owner_interval_ns",0)+ns-pending[0]
                                        pending=None
                            stats["last_rows"]=(stats["last_rows"]+[item])[-12:]
                except BaseException as e:failure=dict(type=type(e).__name__,text=str(e))
                stats["prefix_error"]=failure;stats["elapsed_observation_ns"]=None if start is None else last-start
                times=stats.pop("owner_intervals");stats["owner_interval_count"]=len(times)
                stats["owner_interval_total_ns"]=sum(r["ns"]for r in times)
                stats["owner_intervals_last"]=times[-20:];stats["owner_intervals_max"]=sorted(times,key=lambda r:r["ns"],reverse=True)[:20]
                data["full_buffer_prefix"]=stats
            roles[role]=data
        row["roles"]=roles
        trace=root/"run"/("paired-"+group+".strace")
        if trace.is_file():
            raw=read(trace);lines=raw.decode().splitlines()
            row["trace"]=dict(**pin(raw),lines=len(lines),first=lines[:15],last=lines[-50:])
            samples=[line for line in lines if " | "in line][:30]
            row["trace"]["read_payload_format"]=samples
        report["groups"].append(row)
    controls=root/"run/trace-controls/CONTROLS.json"
    if controls.is_file():report["trace_process_controls"]=loads(read(controls))
    report["producer_stdout"]=read(root/"outer/capture.stdout").decode()
    return report
def main(archive,output):
    output.mkdir(exist_ok=False,parents=True);restore(archive,output/"restored",ROOT/"PINS.json")
    root=output/"restored/complete";report=inspect(root)
    (output/"INSPECT.json").write_bytes(enc(report))
    print("INSPECT_BEGIN");print(enc(report).decode(),end="");print("INSPECT_END")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();main(a.archive,a.output)
