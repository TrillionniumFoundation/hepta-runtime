#!/usr/bin/env python3
"""Receive complete original chunk envelopes locally; no native action or archive execution."""
import argparse,base64,hashlib,json,os,re,stat
from pathlib import Path

FIELDS=("st_dev","st_ino","st_uid","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
HEX=re.compile(r"[0-9a-f]{64}")
def need(ok,msg):
    if not ok: raise ValueError(msg)
def digest(b): return hashlib.sha256(b).hexdigest()
def pairs(xs):
    out={}
    for k,v in xs:
        need(k not in out,"duplicate JSON key")
        out[k]=v
    return out
def loads(b): return json.loads(b,object_pairs_hook=pairs)
def stamp(s): return {k:getattr(s,k) for k in FIELDS}
def read(p,maximum=1024*1024):
    p=p.absolute()
    need(p.resolve(strict=True)==p,"direct local input")
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and 0<=s.st_size<=maximum,"local input type/size")
        with os.fdopen(os.dup(fd),"rb") as f: b=f.read(maximum+1)
        need(len(b)==s.st_size and stamp(s)==stamp(os.fstat(fd))==stamp(p.lstat()),"input changed")
    finally: os.close(fd)
    return b,{"path":str(p),"bytes":len(b),"sha256":digest(b),"identity":stamp(s)}
def write(p,b):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(os.dup(fd),"wb") as f:
            f.write(b);f.flush();os.fsync(f.fileno())
    finally:os.close(fd)
    back,pin=read(p,max(len(b),1))
    need(back==b,"output readback")
    return pin
def envelope(p):
    b,pin=read(p);o=loads(b)
    need(isinstance(o,dict) and set(o)=={"request","result"},"original request/result envelope")
    r=o["result"]
    need(r.get("isError") is not True and isinstance(r.get("content"),list) and len(r["content"])==1 and r["content"][0].get("type")=="text","successful single text response")
    text=r["content"][0]["text"]
    need(isinstance(text,str),"original text")
    return o["request"],text.encode(),loads(text),pin
def file_body(p,expected_path):
    req,_,dto,pin=envelope(p)
    need(req.get("host")=="x230" and req.get("paths")==[expected_path],"original file request")
    need(dto.get("atomic_snapshot") is False and dto.get("encoding")=="utf-8" and dto.get("snapshot_scope")=="independent_file" and dto.get("truncated") is False and len(dto.get("files",[]))==1,"complete independent file")
    f=dto["files"][0]
    need(set(f)=={"eof","path","sha256","size","text","version"} and f["path"]==expected_path and f["eof"] is True,"file identity")
    need(isinstance(f["version"],str) and re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+",f["version"]),"version syntax")
    dev,ino,size,mt,ct=map(int,f["version"].split(":"))
    need(dev>0 and ino>0 and size==f["size"] and mt>0 and ct>0,"version size")
    b=f["text"].encode()
    need(len(b)==f["size"] and digest(b)==f["sha256"],"complete file bytes")
    return b,f,pin,req
def report_body(p,expected_path):
    small=p/"report-read-01.json"
    if small.exists():
        b,f,pin,_=file_body(small,expected_path)
        return b,f,[pin]
    req,_,info,pin=envelope(p/"report-file-info-01.json")
    need(req=={"host":"x230","path":expected_path} and info["path"]==expected_path,"original report file_info")
    need(type(info["size"]) is int and 65536<info["size"]<=16*1024**2 and HEX.fullmatch(info["sha256"]),"bounded original binary report")
    version=info["version"]
    need(isinstance(version,str) and re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+",version) and int(version.split(":")[2])==info["size"],"report version")
    body=bytearray();proof=[pin]
    for i in range((info["size"]+47999)//48000):
        req,_,x,pin=envelope(p/f"report-binary-read-{i:02d}.json");proof.append(pin)
        need(req=={"host":"x230","path":expected_path,"offset":len(body),"limit":48000,"expected_version":version},"original binary request")
        need(set(x)=={"chunk_sha256","data_base64","eof","next_offset","offset","path","size","version"},"original binary result")
        need(x["path"]==expected_path and x["offset"]==len(body) and x["size"]==info["size"] and x["version"]==version,"binary identity")
        enc=x["data_base64"].encode("ascii");b=base64.b64decode(enc,validate=True)
        need(base64.b64encode(b)==enc and len(b)==min(48000,info["size"]-len(body)) and digest(b)==x["chunk_sha256"],"binary chunk bytes")
        body.extend(b)
        need(x["next_offset"]==len(body) and x["eof"] is (len(body)==info["size"]),"binary cursor/EOF")
    need(len(body)==info["size"] and digest(body)==info["sha256"],"whole original binary report")
    return bytes(body),info,proof
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--operations-root",type=Path,required=True)
    ap.add_argument("--remote-root",required=True)
    ap.add_argument("--archive-name",required=True)
    ap.add_argument("--report-sha256",required=True)
    ap.add_argument("--expected-job",required=True)
    a=ap.parse_args();p=a.operations_root.absolute();proof=[]
    need(a.archive_name in ("qualification-ci-01.tar.xz","performance-01.tar.xz"),"fixed archive kind")
    need(HEX.fullmatch(a.report_sha256),"report digest")
    sr,tb,t,sp=envelope(p/"status-01.json");proof.append(sp)
    rr,rb,r,rp=envelope(p/"read-complete-01.json");proof.append(rp)
    need(sr=={"host":"x230","job_id":a.expected_job} and rr=={"host":"x230","job_id":a.expected_job,"stdout_offset":0,"stderr_offset":0,"limit":16384},"original capture requests")
    need(t["job_id"]==r["job_id"]==a.expected_job and t["state"]=="succeeded" and type(t["exit_code"]) is int and t["exit_code"]==0,"capture success")
    need(all(t[k] is True for k in ("output_complete","output_durable","terminal_publication_confirmed")) and type(t["terminal_publication_protocol"]) is int and t["terminal_publication_protocol"]==1,"strong capture terminal")
    need(all(t[k] is False for k in ("automatic_retry","cancelled","timed_out")),"capture no retry/cancel/timeout")
    streams={}
    for k in ("stdout","stderr"):
        x=r[k];b=bytes.fromhex(x["bytes_hex"]);c=t["log_bytes"][k]
        need(x["offset"]==0 and x["eof"] is True and len(b)==x["size"]==x["next_offset"]==c["seen"]==c["stored"],"complete native stream")
        need(b.decode()==x["text"] and t["log_synced"][k] is True and t["log_truncated"][k] is False and t["log_errors"][k] is None,"native stream integrity")
        streams[k]=b
    need(not streams["stderr"],"capture stderr")
    footer=loads(streams["stdout"].splitlines()[-1])
    report_path=a.remote_root+"/report.json"
    report_b,report_f,report_proof=report_body(p,report_path);proof.extend(report_proof)
    need(digest(report_b)==a.report_sha256 and footer["report"]["source_path"]==report_path and footer["report"]["bytes"]==len(report_b) and footer["report"]["sha256"]==digest(report_b),"native footer report binding")
    need(footer["passed"] is True and footer["candidate_adopted"] is False and footer["no_workload_executed"] is True,"capture only")
    report=loads(report_b);archive=report["archive"]["identity"]
    need(report["transfer"]["archive"]==archive and archive["source_path"]==a.remote_root+"/"+a.archive_name,"archive identity")
    transfer_path=a.remote_root+"/"+a.archive_name+".chunks/manifest.json"
    mb,mf,mp,_=file_body(p/"transfer-manifest-read-01.json",transfer_path);proof.append(mp)
    mpin=report["transfer"]["manifest"]
    need(mpin["source_path"]==transfer_path and mpin["bytes"]==len(mb) and mpin["sha256"]==digest(mb),"transfer manifest binding")
    m=loads(mb)
    need(m["archive"]==archive and m["maximum_decoded_chunk_bytes"]==48000 and m["maximum_text_file_bytes"]==64000,"transfer contract")
    chunks=m["chunks"]
    need(len(chunks)==report["transfer"]["chunks"]==(archive["bytes"]+47999)//48000,"chunk count")
    body=bytearray()
    for i,c in enumerate(chunks):
        need(set(c)=={"path","offset","bytes","sha256","base64_bytes","base64_sha256"} and c["path"]==a.remote_root+"/"+a.archive_name+f".chunks/chunk-{i:05d}.b64","chunk identity")
        need(c["offset"]==len(body) and c["bytes"]==min(48000,archive["bytes"]-len(body)) and c["base64_bytes"]==4*((c["bytes"]+2)//3)<=64000,"chunk sequence")
        need(all(isinstance(c[k],str) and HEX.fullmatch(c[k]) for k in ("sha256","base64_sha256")),"chunk digest syntax")
        enc,f,pin,req=file_body(p/f"archive-chunk-read-{i:03d}.json",c["path"]);proof.append(pin)
        need(req=={"host":"x230","paths":[c["path"]],"max_file_bytes":65536,"max_response_bytes":131072},"single original chunk request")
        need(len(enc)==c["base64_bytes"] and digest(enc)==c["base64_sha256"]==f["sha256"],"encoded chunk binding")
        enc.decode("ascii");b=base64.b64decode(enc,validate=True)
        need(base64.b64encode(b)==enc and len(b)==c["bytes"] and digest(b)==c["sha256"],"decoded chunk binding")
        body.extend(b)
    need(len(body)==archive["bytes"] and digest(body)==archive["sha256"],"whole compressed archive")
    for pin in proof:
        _,current=read(Path(pin["path"]));need(current==pin,"original envelope changed after checks")
    out=p/"assembled-01";out.mkdir(mode=0o700)
    outputs={}
    for name,b in [(a.archive_name,bytes(body)),("actual-export-report-01.json",report_b),("actual-transfer-manifest-01.json",mb),("actual-capture-native-terminal-01.json",tb),("actual-capture-native-read-01.json",rb),("complete-stdout-01.log",streams["stdout"]),("complete-stderr-01.log",streams["stderr"])]:
        outputs[name]=write(out/name,b)
    receipt={"schema":"r29-local-original-archive-reception/v1","passed":True,"native_actions":False,"archive_extracted":False,"archive_code_executed":False,"full_consumer_still_required":True,"candidate_adopted":False,"original_envelopes":proof,"outputs":outputs}
    write(out/"reception-receipt-01.json",(json.dumps(receipt,indent=2)+"\n").encode())
    print(json.dumps({"passed":True,"chunks":len(chunks),"archive_bytes":len(body),"archive_sha256":digest(body),"output":str(out),"full_consumer_still_required":True}))
if __name__=="__main__":main()
