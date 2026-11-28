"""Reopen the complete uploaded independent proof and report admitted runtime pins."""
from pathlib import Path
import argparse,hashlib,io,json,stat,zipfile
def require(value,message):
    if not value:raise ValueError(message)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode()
def run(path,output):
    raw=path.read_bytes()
    require(pin(raw)==dict(bytes=9650215,sha256="14176eee9a1dd33331c1235465818bd528c7a0fd57486d2aa5c12e0b89ec3b0e"),"complete uploaded independent ZIP")
    members={};payload={}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for item in archive.infolist():
            name=item.filename;p=Path(name)
            require(not p.is_absolute() and ".." not in p.parts and name not in members,"unique ordinary ZIP path")
            mode=(item.external_attr>>16)&0xffff
            require(not stat.S_ISLNK(mode) and (stat.S_IFMT(mode) in (0,stat.S_IFREG,stat.S_IFDIR)),"ordinary ZIP member")
            data=archive.read(item)
            members[name]=dict(pin(data),mode=mode)
            if not item.is_dir():payload[name]=data
    expected={"proof/"+n for n in ("ARCHIVE.json","GUARDED.json","RESULT.json","verify.stdout","verify.stderr","uploaded-manifest.json")}
    expected|={"source/"+n for n in ("TARGET.json","read_archive.py","verify.py","README.md","SOURCE.json")}
    require(set(payload)==expected,"complete fixed independent uploaded file set")
    require(pin(payload["proof/GUARDED.json"])==dict(bytes=39604849,sha256="f790067e819c8e42fbff9eed909ce20af1d6ae16f08eace9b752ecfbe4202e93"),"full actual guard report")
    require(pin(payload["source/SOURCE.json"])==dict(bytes=953,sha256="bffbd8b4e51bf406d22da90e8c06607ea113b7088a21c3e5492fff296b110288"),"independent frozen source manifest")
    source=json.loads(payload["source/SOURCE.json"])
    for name,row in source["files"].items():
        data=payload["source/"+name]
        require(pin(data)=={k:row[k] for k in ("bytes","sha256")},"complete independent source member")
        require(hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()==row["git_blob"],"actual source Git blob")
    proof=json.loads(payload["proof/GUARDED.json"]);result=json.loads(payload["proof/RESULT.json"])
    require(proof["before"]==proof["after"] and len(proof["before"])==55952 and len(proof["probes"])==12,"complete retained readonly proof")
    require(result["status"]=="INDEPENDENT_COMPLETE_PINNED_ANCHOR_READ_PASS" and result["native_executions"]==result["rust_executions"]==0 and result["before_after_unchanged"] is True,"completed exact independent result")
    require(payload["proof/verify.stderr"]==b"" and payload["proof/verify.stdout"]==encoded(result),"complete successful final streams")
    archive=json.loads(payload["proof/ARCHIVE.json"]);manifest_raw=payload["proof/uploaded-manifest.json"];manifest=json.loads(manifest_raw)
    require(pin(manifest_raw)==archive["manifest"] and archive["logical_files"]==len(manifest["files"])==48545 and archive["logical_bytes"]==sum(r["bytes"] for r in manifest["files"].values())==3512620939,"complete archived producer manifest binding")
    complete=proof["evidence"]["evidence"]
    require(complete["fresh_build"]["status"]=="COMPLETE_NATIVE_CALLABLE_BUILD_READBACK_PASS" and complete["actual_producer_processes"]==13,"actual full native build and producer custody")
    build_prefix="restored/prior/run/semantic/build/"
    pins={n:row for n,row in manifest["files"].items() if n.startswith(build_prefix) and (n.endswith(("/module.image.bin","/manifest.json","/callable.image.bin","/BUILD.json","/BINDING.json")))}
    require(len([n for n in pins if n.endswith("/module.image.bin")])==3,"two semantic images and one actual packer")
    packed=pins[build_prefix+"callable/callable.image.bin"]
    require(complete["fresh_build"]["image"]=={k:packed[k] for k in ("bytes","sha256")},"full actual compiled packed image")
    out=dict(status="COMPLETE_UPLOADED_INDEPENDENT_PROOF_READ_PASS",zip=pin(raw),members=members,
        complete_uploaded_files=len(payload),complete_uploaded_bytes=sum(len(v) for v in payload.values()),
        guard_entries=len(proof["before"]),guard_probes=len(proof["probes"]),fresh_build=complete["fresh_build"],
        runtime_artifact_pins=pins,original_syscalls=complete["original_syscalls"],
        actual_producer_processes=complete["actual_producer_processes"],native_executions=0,rust_executions=0,
        evidence_reexecution=False)
    output.write_bytes(encoded(out));print(encoded(out).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();run(a.archive,a.output)
