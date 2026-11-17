"""Stream every retained capture ZIP/TAR byte; never execute captured code."""
# Copyright 2026 Muvon Un Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



from pathlib import Path, PurePosixPath
import hashlib, json, os, shutil, stat, sys, tarfile, urllib.request, zipfile

def require(ok,message):
    if not ok:raise ValueError(message)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def put(path,obj):
    with path.open("x",encoding="utf-8") as stream:
        json.dump(obj,stream,sort_keys=True,indent=2,allow_nan=False);stream.write("\n")
def safe(name):
    p=PurePosixPath(name)
    require(type(name) is str and name and not p.is_absolute() and p.as_posix()==name
            and all(x not in ("",".","..") for x in p.parts),"unsafe archive path")
def main():
    config=Path(sys.argv[1]);out=Path(sys.argv[2])
    require(not out.exists(),"fresh archive readback directory");out.mkdir(parents=True)
    specs=json.loads(config.read_bytes());summaries=[]
    selected={"BUILD_PASS.json","BUILD_ORIGIN.json","INSTALLED_SOURCE_UNCHANGED.json",
              "production/BUILD.json","production/build/public-task-batch/manifest.json",
              "journal/task-pump/manifest.json","trace/task-pump/manifest.json","instances/task-pump/manifest.json",
              "public/CAPTURE.json","NATIVE_ORIGIN.json","DOMAIN_ORIGIN.json","BATCH_ORIGIN.json",
              "DEPENDENCIES.json","run.json"}
    for spec in specs:
        target=out/str(spec["id"]);target.mkdir()
        if "local_zip" in spec:
            archive=Path(spec["local_zip"])
            require(archive.is_file() and not archive.is_symlink(),"owned existing regular ZIP")
            with archive.open("rb") as source:
                h=hashlib.sha256();count=0
                while b:=source.read(1<<20):h.update(b);count+=len(b)
        else:
            archive=target/"artifact.zip"
            with urllib.request.urlopen(spec["url"],timeout=60) as source,archive.open("xb") as sink:
                h=hashlib.sha256();count=0
                while b:=source.read(1<<20):sink.write(b);h.update(b);count+=len(b)
        require({"bytes":count,"sha256":h.hexdigest()}=={k:spec[k] for k in ("bytes","sha256")},"complete ZIP bytes")
        print(json.dumps({"artifact":spec["id"],"stage":"ZIP_SHA256_PASS","bytes":count}),flush=True)
        with zipfile.ZipFile(archive) as z:
            require(len(z.infolist())==2 and set(z.namelist())=={"archive.json","capture.tar.gz"},"ZIP member set")
            receipt_raw=z.read("archive.json");receipt=json.loads(receipt_raw)
            require(receipt["git_head"]==spec["head"] and receipt["run_id"]==str(spec["run_id"])
                    and receipt["run_attempt"]=="1" and receipt["label"]==spec["label"]
                    and receipt["source_manifest_sha256"]==spec["package_sha256"],"producer receipt")
            require(receipt["qualification_inferred_from_archive"] is False
                    and receipt["captured_tree_modified_by_export"] is False,"archive scope")
            with z.open("capture.tar.gz") as stream:
                h=hashlib.sha256();count=0
                while b:=stream.read(1<<20):h.update(b);count+=len(b)
            require({"bytes":count,"sha256":h.hexdigest()}==receipt["archive"],"complete inner archive bytes")
            seen={};source_rows={};package_raw=None;manifest_raw=None;manifest=None;expected=None;kept={}
            with z.open("capture.tar.gz") as zipped,tarfile.open(fileobj=zipped,mode="r|gz") as tar:
                for item in tar:
                    require(item.name.startswith("capture/") and item.isfile() and not item.issym() and not item.islnk(),"regular capture file")
                    name=item.name.removeprefix("capture/");safe(name);require(name not in seen,"duplicate capture member")
                    stream=tar.extractfile(item);require(stream is not None,"member stream")
                    source_member=name.startswith("ci-package/")
                    keep=(not seen or name in selected or name in ("CI_SOURCE_DECLARATION.json","ci-package/PACKAGE.json"))
                    chunks=[] if keep else None;h=hashlib.sha256();git=hashlib.sha1(b"blob "+str(item.size).encode()+b"\0");count=0
                    with stream:
                        while b:=stream.read(1<<20):
                            h.update(b);git.update(b);count+=len(b)
                            if keep:chunks.append(b)
                    require(count==item.size,"complete member extent")
                    raw=b"".join(chunks) if keep else None
                    if not seen:
                        require(name=="artifact-manifest.json" and item.mode==0o600,"first inventory")
                        require({"bytes":count,"sha256":h.hexdigest()}==receipt["manifest"],"inventory identity")
                        manifest_raw=raw;manifest=json.loads(raw);expected=dict(manifest["files"])
                        require(name not in expected and manifest["schema"]=="hepta.runtime.complete-ci-archive.v2"
                                and manifest["label"]==spec["label"]
                                and manifest["source_manifest_sha256"]==spec["package_sha256"],"manifest provenance")
                        for n,row in expected.items():
                            safe(n);require(set(row)=={"bytes","sha256","mode"},"manifest row")
                        expected[name]={**receipt["manifest"],"mode":0o600}
                    require(name in expected and expected[name]=={"bytes":count,"sha256":h.hexdigest(),"mode":item.mode},"all member bytes/modes")
                    seen[name]={"bytes":count,"sha256":h.hexdigest(),"mode":item.mode,
                                "tar_mtime":item.mtime,"tar_uid":item.uid,"tar_gid":item.gid,"tar_pax_headers":item.pax_headers}
                    if source_member:
                        source_rows[name.removeprefix("ci-package/")]={"bytes":count,"sha256":h.hexdigest(),"git_blob":git.hexdigest(),
                                                                    "mode":"100755" if item.mode&0o111 else "100644"}
                    if name=="ci-package/PACKAGE.json":package_raw=raw
                    if name in selected or name=="CI_SOURCE_DECLARATION.json":
                        dest=target/"selected"/name;dest.parent.mkdir(parents=True,exist_ok=True)
                        with dest.open("xb") as f:f.write(raw)
                        kept[name]={"bytes":count,"sha256":h.hexdigest()}
            require(expected is not None and set(seen)==set(expected),"complete capture member set")
            require(receipt["readback"]=={"files":len(seen),"logical_bytes":sum(r["bytes"] for r in seen.values())},"complete archive counts")
            require(package_raw is not None and digest(package_raw)==spec["package_sha256"],"exact complete source package")
            declared=json.loads(package_raw)["files"];actual=dict(source_rows);actual.pop("PACKAGE.json")
            require(actual==declared,"all original Git source identities")
            declaration=json.loads((target/"selected/CI_SOURCE_DECLARATION.json").read_bytes())
            require(declaration["git_head"]==spec["head"] and declaration["run_id"]==str(spec["run_id"])
                    and declaration["manifest_sha256"]==spec["package_sha256"] and declaration["label"]==spec["label"],
                    "complete source custody")
            for n,mode in manifest["directories"].items():safe(n);require(type(mode) is int and 0<=mode<=0o777,"directory inventory")
            require(z.testzip() is None,"complete outer CRC")
        with (target/"artifact-manifest.json").open("xb") as f:f.write(manifest_raw)
        with (target/"archive.json").open("xb") as f:f.write(receipt_raw)
        with (target/"PACKAGE.json").open("xb") as f:f.write(package_raw)
        report={"schema":"hepta.public111.local-complete-archive-readback.v1","status":"PASS",
                "artifact":{k:v for k,v in spec.items() if k!="url"},"archive":receipt["archive"],"manifest":receipt["manifest"],
                "members":len(seen),"logical_bytes":receipt["readback"]["logical_bytes"],"directories":len(manifest["directories"]),
                "source_files":len(source_rows),"selected_complete_files":kept,
                "all_member_bytes_and_modes_equal":True,"all_source_git_objects_equal":True,"native_or_rust_executed":False,
                "captured_reader_executed":False,"archive_is_semantic_qualification":False}
        put(target/"MEMBERS.json",seen);put(target/"READBACK.json",report);summaries.append(report)
        put(out/("complete-"+str(spec["id"])+".json"),report)
        print(json.dumps({"artifact":spec["id"],"label":spec["label"],"members":len(seen),"logical_bytes":report["logical_bytes"],"status":"COMPLETE_ARCHIVE_READBACK_PASS"}),flush=True)
    put(out/"COMPLETE.json",{"schema":"hepta.public111.complete-existing-archives.v1","status":"PASS","archives":summaries,
                            "complete_original_zip_bytes":sum(s["artifact"]["bytes"] for s in summaries),
                            "complete_members":sum(s["members"] for s in summaries),
                            "complete_logical_bytes":sum(s["logical_bytes"] for s in summaries),
                            "native_or_rust_executed":False,"captured_reader_executed":False})
if __name__=="__main__":main()
