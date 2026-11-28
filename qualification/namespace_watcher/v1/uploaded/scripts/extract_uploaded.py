"""Restore every byte of the uploaded Watcher reader artifact without executing it."""
import argparse,hashlib,io,json,os,stat,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/"reader"))
from reader_common import read,loads,encoded,pin,require,files,source
def run(archive,output):
    binding=loads(read(ROOT/"UPLOADED-PINS.json"));raw=read(archive)
    require(pin(raw)==binding["uploaded"]["zip"],"entire immutable uploaded reader ZIP")
    output.mkdir(parents=True,exist_ok=False);expected={};directories=set();members=[]
    with zipfile.ZipFile(io.BytesIO(raw))as z:
        require(len(set(z.namelist()))==len(z.infolist()),"unique complete ZIP member names")
        for item in z.infolist():
            name=item.filename;p=Path(name.rstrip("/"));mode=(item.external_attr>>16)&0xffff
            require(name and not p.is_absolute()and".."not in p.parts and p.as_posix()==name.rstrip("/")
                and p.parts[0]in binding["uploaded"]["roots"]and not item.flag_bits&1,
                "ordinary relative complete uploaded member")
            if item.is_dir():
                require(not stat.S_ISLNK(mode)and item.file_size==0,"ordinary empty ZIP directory")
                (output/p).mkdir(parents=True,exist_ok=True);directories.add(p.as_posix());continue
            require(not stat.S_ISLNK(mode)and(not stat.S_IFMT(mode)or stat.S_ISREG(mode)),
                "no linked or special uploaded file")
            body=z.read(item);require(len(body)==item.file_size,"entire uploaded ZIP member extent")
            actual_mode=stat.S_IMODE(mode)or 0o644
            require(actual_mode==0o644,"unchanged uploaded ordinary source and evidence file mode")
            target=output/p;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb")as f:f.write(body)
            target.chmod(actual_mode)
            expected[name]=dict(**pin(body),mode=actual_mode)
            members.append(dict(name=name,bytes=len(body),sha256=pin(body)["sha256"],zip_mode=mode))
    require(len(expected)==binding["uploaded"]["files"]and {Path(n).parts[0]for n in expected}==set(binding["uploaded"]["roots"]),
        "whole uploaded artifact, no omission or extra root")
    require(files(output)==expected,"every restored uploaded byte and mode read again")
    frozen=ROOT/"reader";require(read(output/"source/SOURCE.json")==read(frozen/"SOURCE.json"),
        "original entire frozen V5 source manifest")
    source(output/"source",read(frozen/"SOURCE.json"))
    require(files(output/"source")==files(frozen),"all uploaded source files equal frozen reader bytes")
    report=dict(status="COMPLETE_UPLOADED_WATCHER_READER_RESTORE_PASS",zip=pin(raw),
        files=len(expected),bytes=sum(r["bytes"]for r in expected.values()),members=members,
        all_file_bytes_and_modes=True,native_executions=0,rust_executions=0,application_executions=0)
    return report
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--report",type=Path,required=True);a=p.parse_args()
    result=run(a.archive.resolve(strict=True),a.output.absolute())
    a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_bytes(encoded(result))
    print(encoded({k:result[k]for k in("status","zip","files","bytes","all_file_bytes_and_modes","application_executions")}).decode(),end="")
