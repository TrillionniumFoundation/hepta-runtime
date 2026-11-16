"""Retain and reread exact locked crate archives; never consult a producer cache while reading."""
from pathlib import Path, PurePosixPath
import io, json, tarfile, tomllib
import catalog_ci_support as c

def locked(original):
    lock=tomllib.loads(c.regular(original/"original-source/Cargo.lock").decode())
    rows={}
    for item in lock["package"]:
        if item.get("source","").startswith("registry+"):
            key=item["name"]+"-"+item["version"]
            c.need(key not in rows and type(item.get("checksum"))is str,"one exact locked registry package")
            rows[key]=item
    return rows

def capture(original,output):
    pins=locked(original);registry=c.read_json(original/"registry.json")
    metadata=c.read_json(original/"processes/cargo-metadata.stdout")
    by={}
    for item in metadata["packages"]:
        if item.get("source") is not None:
            key=item["name"]+"-"+item["version"]
            c.need(key not in by and key in registry and key in pins,"exact metadata registry member")
            by[key]=item
    c.need(set(by)==set(registry),"all actual metadata packages retained")
    folder=output/"registry-archives";folder.mkdir()
    rows={}
    for key,item in sorted(by.items()):
        source=Path(item["manifest_path"]).parent
        c.need(source.name==key and source.parent.parent.name=="src","Cargo source layout")
        archive=source.parents[2]/"cache"/source.parent.name/(key+".crate")
        raw=c.regular(archive)
        c.need(c.sha(raw)==pins[key]["checksum"] and item["source"]==pins[key]["source"],"actual locked crate checksum")
        c.put(folder/(key+".crate"),raw)
        rows[key]={"origin":str(archive),"path":"registry-archives/"+key+".crate","archive":c.pin(raw),
            "source":item["source"],"id":item["id"]}
    c.put(output/"registry-archives.json",{"schema":"hepta.runtime.configured-catalog-locked-registry.v1",
        "packages":rows,"original_lock":c.pin(c.regular(original/"original-source/Cargo.lock")),
        "producer_cache_used_only_during_capture":True,"reader_requires_producer_cache":False})
    return len(rows)

def verify(original,output):
    r=c.Reader(output);manifest=r.document("registry-archives.json")
    c.need(manifest["schema"]=="hepta.runtime.configured-catalog-locked-registry.v1"
        and manifest["producer_cache_used_only_during_capture"] is True
        and manifest["reader_requires_producer_cache"] is False,"offline locked registry scope")
    pins=locked(original);registry=c.read_json(original/"registry.json")
    c.need(manifest["original_lock"]==c.pin(c.regular(original/"original-source/Cargo.lock"))
        and set(manifest["packages"])==set(registry),"all actual registry packages and target lock")
    count=0;total=0
    for key,row in sorted(manifest["packages"].items()):
        c.need(row["path"]=="registry-archives/"+key+".crate" and row["source"]==pins[key]["source"]
            and row["id"]==registry[key]["id"] and Path(row["origin"]).is_absolute(),"archive roles/recorded origin")
        raw=r.raw(row["path"],row["archive"])
        c.need(c.sha(raw)==pins[key]["checksum"],"immutable Cargo.lock archive checksum")
        members={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as archive:
            for member in archive:
                name=PurePosixPath(member.name)
                c.need(not name.is_absolute() and ".." not in name.parts and name.parts[0]==key,"crate archive path")
                if member.isdir():continue
                c.need(member.isfile(),"only owned regular crate source members")
                relative=PurePosixPath(*name.parts[1:]).as_posix()
                c.need(relative not in members and relative not in (".",""),"one complete crate source member")
                stream=archive.extractfile(member);c.need(stream is not None,"crate source extent")
                body=stream.read();c.need(len(body)==member.size,"complete decompressed crate bytes")
                actual=c.regular(original/"registry-source"/key/relative)
                c.need(body==actual and c.pin(body)==registry[key]["files"][relative],"complete locked dependency source")
                members[relative]=c.sha(body);count+=1;total+=len(body)
        source_root=original/"registry-source"/key
        checksum=c.read_json(source_root/".cargo-checksum.json")
        c.need(set(checksum)=={"files","package"} and checksum["package"]==c.sha(raw)
            and checksum["files"] in ({},members),"Cargo generated source checksum table")
        generated={".cargo-checksum.json"}
        if ".cargo-ok" in registry[key]["files"]:generated.add(".cargo-ok")
        c.need(set(registry[key]["files"])==set(members)|generated,"no additional unbound crate implementation")
    return {"status":"COMPLETE_LOCKED_REGISTRY_ARCHIVES_READONLY_PASS","packages":len(registry),
        "source_members":count,"complete_decompressed_bytes":total,"files":r.files,
        "producer_cache_reads":0,"process_launches":0}
