"""Restore only exact already-built producer artifacts; application executions are separate."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,stat,subprocess,sys,tarfile,zipfile
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path[:0]=[str(HERE/"build_reader"),str(HERE)]
from restore_graph import download,safe
import restore_graph,read_graph,read_only_guard as guard,archive_stream
from read_primitives import require,pin,doc
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
def flat_archive(path,identity,output):
    require(pin(path)==identity["zip"],"complete fixed fixture ZIP")
    require(not output.exists(),"fresh fixture restoration");output.mkdir(parents=True)
    with zipfile.ZipFile(path) as z:
        require(set(z.namelist())=={"ARCHIVE.json","FILES.json","evidence.tar.gz"} and len(z.infolist())==3,"full fixture outer ZIP")
        index=json.loads(z.read("FILES.json"));wanted={r["path"]:r for r in index["files"]};require(len(wanted)==len(index["files"])==identity["files"],"fixture archive member count")
        with z.open("evidence.tar.gz") as src:
            h=archive_stream.Hashing(src);seen=set()
            with tarfile.open(fileobj=h,mode="r|gz") as tar:
                for m in tar:
                    safe(m.name);require(m.isfile() and m.name in wanted and m.name not in seen,"ordinary unique complete fixture evidence")
                    r=wanted[m.name];require(m.size==r["bytes"] and m.mode==r["mode"],"fixture evidence extent/mode")
                    p=output/m.name;p.parent.mkdir(parents=True,exist_ok=True)
                    with tar.extractfile(m) as a,p.open("xb") as b:
                        shutil.copyfileobj(a,b)
                    os.chmod(p,m.mode);require(pin(p)=={k:r[k] for k in ("bytes","sha256")},"complete fixture member bytes");seen.add(m.name)
            while h.read(1<<20):pass
            require(h.pin()==identity["archive"],"full compressed fixture TAR")
        expected={"status":"COMPLETE_ARCHIVE_BYTES_PASS","files":identity["files"],"logical_bytes":identity["logical_bytes"],"archive":identity["archive"]}
        require(json.loads(z.read("ARCHIVE.json"))==expected and seen==set(wanted) and sum(r["bytes"] for r in wanted.values())==identity["logical_bytes"],"complete fixed fixture archive proof")
    return expected
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    output=a.output.absolute();require(not output.exists(),"fresh dependency restoration");output.mkdir(parents=True)
    inputs=doc(HERE/"INPUTS.json")
    native=restore_graph.restore(output/"shared")
    fixture_zip=output/"fixture.zip";download(fixture_zip,inputs["native_fixture"]["artifact"])
    proof=flat_archive(fixture_zip,inputs["native_fixture"],output/"fixture")
    put(output/"FIXTURE_ARCHIVE_READ.json",proof)
    old_source=output/"fixture/recipe-source"
    source_rows=doc(HERE/"build_reader/SOURCE_MANIFEST.json")["files"]
    for r in source_rows:
        require((old_source/r["path"]).read_bytes()==(HERE/"build_reader"/r["path"]).read_bytes(),"complete frozen fixture build reader source")
    require((old_source/"SOURCE_MANIFEST.json").read_bytes()==(HERE/"build_reader/SOURCE_MANIFEST.json").read_bytes(),"exact retained reader manifest")
    read_graph.prepare(native)
    read=guard.guarded(lambda:read_graph.verify(native,output/"fixture/capture"),roots=[native,output/"fixture",HERE],foreign_path=Path("/dev/null"))
    put(output/"NATIVE_DEPENDENCY_READONLY.json",read)
    n=output/"fixture/capture/build/wait-control/task-pump-fixture.elf"
    require(pin(n)==inputs["native_fixture"]["elf"],"fixed WAIT test ELF")
    original_zip=output/"original.zip";download(original_zip,inputs["original"]["artifact"])
    full=archive_stream.archive(original_zip,inputs["original"],lambda name:True,output=output/"original")
    put(output/"ORIGINAL_ARCHIVE_READ.json",full)
    command=[sys.executable,"-I","-S","-B",str(HERE/"original_read.py"),"--capture",str(output/"original")]
    with (output/"original-reader.stdout").open("xb") as stdout,(output/"original-reader.stderr").open("xb") as stderr:
        process=subprocess.run(command,stdout=stdout,stderr=stderr,check=False)
    put(output/"ORIGINAL_READER_PROCESS.json",{"command":command,"exit_code":process.returncode,"stdout":pin(output/"original-reader.stdout"),"stderr":pin(output/"original-reader.stderr"),"native_or_rust_executions":0})
    require(process.returncode==0 and not (output/"original-reader.stderr").read_bytes(),"independent complete original build reader")
    old=doc(output/"original-reader.stdout");require(len(old["probes"])==11 and old["before"]==old["after"],"strict original read-only guard")
    expected=old["evidence"]["original"]["binaries"]["hepta-batch-sdk-current-original-oracle"]
    o=output/"original/original"/expected["path"]
    require(pin(o)=={k:expected[k] for k in ("bytes","sha256")},"strict original binary custody")
    result={"status":"EXACT_ALREADY_BUILT_INPUTS_READY","native":{"path":str(n),**pin(n)},"original":{"path":str(o),**pin(o)},"original_source_commit":inputs["original"]["source"],"native_fixture_source_commit":inputs["native_fixture"]["source"],"application_executions":0,"full_graph_source":"e5d701339c16c4b1bd1801252d2357721452687c"}
    put(output/"BINARIES.json",result);print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
