"""Read the complete preserved failure and inspect libc admission; no HIA/Rust execution."""
from pathlib import Path, PurePosixPath
import argparse,ctypes as C,hashlib,io,json,os,stat,tarfile,zipfile
def need(ok,text):
    if not ok: raise ValueError(text)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def path(name):
    item=PurePosixPath(name)
    need(type(name) is str and name and not item.is_absolute() and item.as_posix()==name
         and all(x not in ("",".","..") for x in item.parts),"contained ordinary archive path")
    return item
def main(archive,output):
    output.mkdir(parents=True,exist_ok=False)
    raw=archive.read_bytes()
    need(pin(raw)==dict(bytes=141585671,sha256="114fb797450dc58552d4e6c0dde02e702e29a649630c6a2f0c22bdfe54b1fdac"),"complete failed ZIP")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        need(z.namelist()==list(dict.fromkeys(z.namelist())) and set(z.namelist())==
            {"audit-record-callable.tar.gz","audit-record-callable.tar.gz.json"} and z.testzip() is None,"complete ZIP members/CRC")
        packed=z.read("audit-record-callable.tar.gz")
        producer=json.loads(z.read("audit-record-callable.tar.gz.json"))
    need(pin(packed)==dict(bytes=141584786,sha256="6d3364f6ab539af356201d019a3e4da47825eb73db74b18c40585fc3ff50f788"),"complete failed TAR")
    need(producer["status"]=="NO_FINAL_GATE" and producer["all_logical_files_reread"] is True
         and producer["all_objects_and_modes_reread"] is True,"actual preserved failure export")
    objects={}; bodies={}; manifest=None
    with tarfile.open(fileobj=io.BytesIO(packed),mode="r:gz") as tar:
        for member in tar:
            path(member.name)
            need(member.isfile() and member.name not in objects,"unique regular complete member")
            with tar.extractfile(member) as stream:body=stream.read()
            need(len(body)==member.size,"all member bytes")
            identity=dict(**pin(body),mode=member.mode);objects[member.name]=identity
            if member.name=="artifact-manifest.json":
                manifest=json.loads(body)
            else:
                need(member.name=="objects/"+identity["sha256"]+"-"+format(member.mode,"03o"),"whole object-addressed bytes/mode")
                # Only small source/reports/streams are retained for diagnosis.
                if len(body)<500000:bodies[member.name]=body
    need(manifest["git_head"]=="8dbcadb5069226ac056a2eee593a43db23031dda" and
        manifest["run_id"]=="44060098314" and manifest["source_manifest_sha256"]==
        "16ab2119292c4e978376d9c3110c86277786ce700a82574b63a18fa844218d29","exact failed producer/source")
    logical=manifest["files"]; expected={}
    for name,row in logical.items():
        path(name)
        need(set(row)=={"bytes","sha256","mode","object"} and row["object"]==
            "objects/"+row["sha256"]+"-"+format(row["mode"],"03o"),"all complete logical bindings")
        value={k:row[k] for k in ("bytes","sha256","mode")}
        need(objects[row["object"]]==value,"every logical file bound to fully read bytes")
        expected[row["object"]]=value
    expected["artifact-manifest.json"]=objects["artifact-manifest.json"]
    need(objects==expected and len(logical)==44747 and sum(x["bytes"] for x in logical.values())==2506029069,
         "complete failed logical domain/object set")
    selected=["run/semantic/CAPTURE.json","run/semantic/processes/processes.json",
              "run/semantic/processes/native-observed.stderr","run/semantic/build/BUILD.json",
              "run/semantic/build/callable/manifest.json","run/semantic/build/callable/BINDING.json"]
    for name in selected:
        row=logical[name];body=bodies[row["object"]]
        destination=output/"failure"/name
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(body);destination.chmod(row["mode"])
    (output/"FAILED_ARCHIVE_MANIFEST.json").write_bytes(encoded(manifest))
    class DlInfo(C.Structure):
        _fields_=[("filename",C.c_char_p),("base",C.c_void_p),("symbol",C.c_char_p),("symbol_address",C.c_void_p)]
    library=C.CDLL(None)
    lookup=library.dladdr;lookup.argtypes=[C.c_void_p,C.POINTER(DlInfo)];lookup.restype=C.c_int
    functions=("__errno_location","openat","fstat","geteuid","read","write","fsync","close",
               "linkat","unlinkat","renameat","fcntl","fdopendir","readdir","closedir")
    rows=[]
    for name in functions:
        pointer=C.cast(getattr(library,name),C.c_void_p).value;info=DlInfo()
        need(lookup(pointer,C.byref(info))!=0 and info.filename,"real loaded symbol")
        original=info.filename.decode();resolved=Path(original).resolve(strict=True);body=resolved.read_bytes()
        identity=pin(body);filename="library-"+identity["sha256"]+".bin"
        if not (output/filename).exists():(output/filename).write_bytes(body)
        rows.append(dict(name=name,pointer=pointer,filename=original,resolved_path=str(resolved),
                         library=identity,library_file=filename,first16_hex=body[:16].hex(),
                         base=info.base,symbol=None if info.symbol is None else info.symbol.decode(),
                         symbol_address=info.symbol_address))
    (output/"PROCESS-MAPS.txt").write_bytes(Path("/proc/self/maps").read_bytes())
    value=dict(schema="hepta.audit-record-callable.libc-inspection.v1",status="OBSERVED",
               failed_head=manifest["git_head"],failed_run=44060098314,failed_job=133959441040,
               complete_zip=pin(raw),complete_tar=pin(packed),logical_files=len(logical),
               logical_bytes=sum(x["bytes"] for x in logical.values()),all_objects_read=True,
               selected_files=selected,actual_libc_symbols=rows,hIA_executions=0,rust_executions=0,
               original_failure_preserved=True,public_handler_qualified=False)
    (output/"REPORT.json").write_bytes(encoded(value))
    print(encoded(value).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();main(a.archive.resolve(strict=True),a.output.absolute())
