"""Download and completely verify the already successful shared123 archive."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,stat,tarfile,urllib.request,zipfile
from read_primitives import require,pin,doc
HERE=Path(__file__).resolve().parent
REPO="TrillionniumFoundation/hepta-runtime"
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        out=super().redirect_request(req,fp,code,msg,headers,newurl)
        if out is not None:out.remove_header("Authorization")
        return out
def download(path,artifact):
    token=os.environ["GH_TOKEN"]
    url="https://api.github.com/repos/"+REPO+"/actions/artifacts/"+str(artifact)+"/zip"
    request=urllib.request.Request(url,headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","User-Agent":"complete-evidence-reader"})
    with urllib.request.build_opener(Redirect()).open(request,timeout=60) as response,path.open("xb") as out:
        while block:=response.read(1<<20):out.write(block)
def safe(name):
    p=PurePosixPath(name)
    require(name and not p.is_absolute() and ".." not in p.parts and p.as_posix()==name,"ordinary archive path")
def restore(output):
    output=Path(output).absolute();require(not output.exists(),"fresh restore root");output.mkdir(parents=True)
    identity=doc(HERE/"SOURCE_INDEX.json");a=identity["artifact"]
    archive=output/"producer.zip";download(archive,a["id"])
    require(pin(archive)==a["zip"],"complete producer ZIP pin")
    target=output/"retained";target.mkdir()
    with zipfile.ZipFile(archive) as z:
        require(set(z.namelist())=={"ARCHIVE.json","FILES.json","evidence.tar.gz"} and len(z.infolist())==3,"outer complete archive set")
        for row in z.infolist():require(not row.is_dir() and not stat.S_ISLNK(row.external_attr>>16),"regular ZIP member")
        index=json.loads(z.read("FILES.json"));receipt=json.loads(z.read("ARCHIVE.json"))
        wanted={r["path"]:r for r in index["files"]};require(len(wanted)==a["files"]==len(index["files"]),"complete member count")
        seen=set();compressed=hashlib.sha256();compressed_bytes=0
        with z.open("evidence.tar.gz") as src,(output/"evidence.tar.gz").open("xb") as out:
            while block:=src.read(1<<20):compressed.update(block);compressed_bytes+=len(block);out.write(block)
        require({"bytes":compressed_bytes,"sha256":compressed.hexdigest()}==a["archive"],"entire compressed TAR")
        with tarfile.open(output/"evidence.tar.gz","r:gz") as tar:
            for member in tar:
                safe(member.name);require(member.isfile() and member.name not in seen and member.name in wanted,"unique complete regular member")
                r=wanted[member.name];require(member.size==r["bytes"] and member.mode==r["mode"],"member extent/mode")
                p=target/member.name;p.parent.mkdir(parents=True,exist_ok=True)
                h=hashlib.sha256();count=0
                with tar.extractfile(member) as stream,p.open("xb") as out:
                    while block:=stream.read(1<<20):h.update(block);count+=len(block);out.write(block)
                require(count==r["bytes"] and h.hexdigest()==r["sha256"],"complete bytes: "+member.name)
                os.chmod(p,member.mode);seen.add(member.name)
        require(seen==set(wanted) and sum(r["bytes"] for r in wanted.values())==a["logical_bytes"],"full archive set")
        expected={"status":"COMPLETE_ARCHIVE_BYTES_PASS","files":a["files"],"logical_bytes":a["logical_bytes"],"archive":a["archive"]}
        require(receipt==expected,"producer archive readback")
        for name in ("ARCHIVE.json","FILES.json"):(output/name).write_bytes(z.read(name))
    result={"status":"COMPLETE_SHARED123_ARCHIVE_RESTORED","zip":a["zip"],"archive":a["archive"],"files":len(seen),"logical_bytes":a["logical_bytes"],"producer_run":identity["run"],"producer_job":identity["job"],"producer_source":identity["composition_source_commit"],"semantic_executions":0}
    (output/"RESTORE.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    return target
