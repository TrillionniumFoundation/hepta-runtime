#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every uploaded author-build byte, then export the actual generated source."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,importlib.util,json,os,shutil,tarfile,urllib.request,urllib.error,zipfile
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def require(v,m):
    if not v:raise ValueError(m)
def pin(p):
    with Path(p).open("rb") as f:return dict(bytes=Path(p).stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def decode(b):
    def unique(rows):
        d={}
        for k,v in rows:
            require(k not in d,"duplicate key");d[k]=v
        return d
    return json.loads(b,object_pairs_hook=unique)
p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
root=a.output.absolute();root.mkdir(parents=True,exist_ok=False)
request=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/14324153449/zip",
    headers={"Authorization":"Bearer "+os.environ["GITHUB_TOKEN"],"Accept":"application/vnd.github+json"})
try:reply=urllib.request.build_opener(NoRedirect()).open(request,timeout=60)
except urllib.error.HTTPError as error:
    require(error.code in (301,302,303,307,308),"redirect");url=error.headers["Location"]
    require(url.startswith("https://"),"https required");reply=urllib.request.urlopen(url,timeout=60)
archive=root/"artifact.zip"
with reply,archive.open("xb") as dest:shutil.copyfileobj(reply,dest,1<<20)
require(pin(archive)==dict(bytes=13252521,sha256="14c3425e7b7616f674ae822f61f67fd16d85687069461c7350e994d49f61b29a"),"whole ZIP")
with zipfile.ZipFile(archive) as z:
    require(set(z.namelist())=={"FILES.json","ARCHIVE.json","evidence.tar.gz"},"ZIP members")
    for name in z.namelist():
        with z.open(name) as incoming,(root/name).open("xb") as dest:shutil.copyfileobj(incoming,dest,1<<20)
    require(z.testzip() is None,"ZIP CRC")
require(pin(root/"evidence.tar.gz")==dict(bytes=12983589,sha256="82a431dbc5b023b528aef4048033514b6e1b2aa004d6c1279a0c76dad88b6edc"),"whole TAR")
index=decode((root/"FILES.json").read_bytes());wanted={r["path"]:r for r in index["files"]+index["directories"]}
require(len(wanted)==1137+47 and len(index["files"])==1137 and len(index["directories"])==47,"complete set")
seen=set();selected={};logical=0
with tarfile.open(root/"evidence.tar.gz","r|gz") as tar:
    for member in tar:
        name=member.name;p=PurePosixPath(name)
        require(not p.is_absolute() and ".." not in p.parts and p.as_posix()==name,"safe path")
        require(name in wanted and name not in seen,"exact unique member");seen.add(name);row=wanted[name]
        require(member.mode==row["mode"] and member.size==row["bytes"],"member metadata")
        require((member.isdir() and row["kind"]=="dir") or (member.isfile() and row["kind"]=="file"),"member kind")
        sec,ns=divmod(row["mtime_ns"],1000000000)
        require(member.pax_headers.get("mtime")==str(sec)+"."+f"{ns:09d}","exact timestamp")
        require({k.removeprefix("HEPTA.xattr.hex.v1."):v for k,v in member.pax_headers.items()
                 if k.startswith("HEPTA.xattr.hex.v1.")}==row["xattrs"],"exact xattrs")
        if member.isdir():continue
        logical+=member.size;reader=tar.extractfile(member);digest=hashlib.sha256();raw=[]
        collect=(name.endswith("/generated/publication_worker.hepta") or name.endswith("/generated/AUTHOR.json")
                 or name.endswith("/BUILD.json") or name.endswith("/modules/publication-worker/manifest.json"))
        while True:
            block=reader.read(1<<20)
            if not block:break
            digest.update(block)
            if collect:raw.append(block)
        require(digest.hexdigest()==row["sha256"],"full member bytes "+name)
        if collect:selected[name]=b"".join(raw)
require(seen==set(wanted) and logical==45613982 and len(selected)==4,"whole uploaded closure")
for name,raw in selected.items():
    if name.endswith(".hepta"):
        text=raw.decode();require(text.encode()==raw,"exact UTF8 source")
        print("GENERATED_SOURCE "+json.dumps({"path":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"text":text}))
    else:print("BUILD_RECORD "+json.dumps({"path":name,"record":decode(raw)}))
(root/"READBACK.json").write_text(json.dumps({"status":"COMPLETE_UPLOADED_AUTHOR_BUILD_READ_PASS",
    "zip":pin(archive),"tar":pin(root/"evidence.tar.gz"),"files":1137,"directories":47,
    "logical_bytes":logical,"native_or_rust_executed":False},sort_keys=True)+"\n")
print((root/"READBACK.json").read_text())
