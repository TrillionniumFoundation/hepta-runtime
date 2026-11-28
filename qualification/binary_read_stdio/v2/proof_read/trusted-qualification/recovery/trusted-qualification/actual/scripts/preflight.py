#!/usr/bin/env python3
"""Validate changed observer custody on two new probes, with zero target/HIA applications."""
from pathlib import Path
import argparse,gzip,os,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require,source_evidence
from check_source import verify as check
from stdio_process import run
from readonly import guarded
from read_kernel import verify as read_kernel
def full(work):
    rows=decode((work/"PROBES.json").read_bytes());require([r["mode"]for r in rows]==["normal","fault"],"fixed two independent probes")
    stats=[]
    for i,row in enumerate(rows):
        folder=work/("probe-"+row["mode"]);p=decode((folder/"PROCESS.json").read_bytes())
        require(p==row["process"]and p["completed"]and not p["timed_out"]and p["timeout_seconds"]==60
            and p["after_reap_proc_absent"]and p["returncode"]==i,"complete independent probe process")
        streams={n:gzip.decompress((folder/(n+".gz")).read_bytes())for n in("stdin","stdout","stderr")}
        for n,value in streams.items():
            require(pin(folder/(n+".gz"))==p["streams"][n]["compressed"]
                and dict(bytes=len(value),sha256=__import__("hashlib").sha256(value).hexdigest())==p["streams"][n]["raw"],
                "whole independent probe stream")
        require(streams["stdin"]==bytes.fromhex(row["input_hex"]),"exact independent input")
        if not i:require(streams["stdout"]==streams["stdin"]+bytes.fromhex(row["file_hex"])and not streams["stderr"],"normal read-FD3 probe")
        else:require(not streams["stdout"]and streams["stderr"]==b"OSError: [Errno 5] Input/output error\n","actual kernel EIO probe")
        stats.append(read_kernel(folder,p,streams["stdin"],streams["stdout"],streams["stderr"],row["query"],dict(fault=bool(i))))
    return dict(status="STDIO_PASSIVE_OBSERVER_PREFLIGHT_PASS",probe_processes=2,
        kernel_calls=[v["calls"]for v in stats],kernel_bytes=[v["trace_bytes"]for v in stats],
        orphans=[len(v["orphans"])for v in stats],original_target_applications=0,hia_applications=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);a=p.parse_args()
    identity=check(ROOT);work=a.work.absolute();require(not work.exists(),"fresh independent observer preflight");work.mkdir(parents=True)
    rows=[]
    for i,mode in enumerate(("normal","fault")):
        payload=b"new-stdio-observer-20261118-"+mode.encode()+b"\n"
        data=b"actual-FD3-observer-data-"+mode.encode()+b"\x00\xff\n"
        path=work/("data-"+mode+".bin");path.write_bytes(data);st=path.stat()
        query=dict(request=dict(path=str(path)),input_selected_stat={k:getattr(st,k)for k in("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")})
        row=dict(mode=mode,query=query,input_hex=payload.hex(),file_hex=data.hex())
        argv=[str(Path(sys.executable).resolve(strict=True)),"-I","-S","-B",str(ROOT/"scripts/preflight_probe.py"),mode,str(path)]
        row["process"]=run(work/("probe-"+mode),argv,payload,observed=False,native=False,input_chunk=7,output_chunk=31,fault=bool(i))
        rows.append(row);(work/"PROBES.json").write_bytes(canonical(rows))
    value=guarded(lambda:full(work),roots=[ROOT,work]);(work/"READONLY.json").write_bytes(canonical(value))
    require(check(ROOT)==identity,"observer preflight changed any source")
    result=dict(status="PASS",source=identity,proof=value["evidence"],guard_probes=11,
        original_target_applications=0,hia_applications=0)
    (work/"GATE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
