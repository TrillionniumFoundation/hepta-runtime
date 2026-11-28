#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Exact retained fresh-build dependencies; complete archive bytes, no semantic replay."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,importlib.util,io,json,os,sys,tarfile,tomllib
import urllib.request,urllib.error,urllib.parse,zipfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,sha
IDENTITY=decode((Path(__file__).resolve().parents[1]/"DEPENDENCY_IDENTITIES.json").read_bytes())
GRAPH=IDENTITY["graph"];REFERENCE=IDENTITY["reference"];ROLES=IDENTITY["roles"]
OLD_GRAPH=Path("/home/runner/work/_temp/text-publication-public-graph/native-build")
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def download(identity,path):
    request=urllib.request.Request(
        "https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(identity["artifact"])+"/zip",
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json",
            "X-GitHub-Api-Version":"2022-11-28"})
    try:response=urllib.request.build_opener(NoRedirect()).open(request,timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301,302,303,307,308),"artifact API redirect")
        location=error.headers["Location"]
        require(urllib.parse.urlparse(location).scheme=="https","artifact transport")
        response=urllib.request.urlopen(location,timeout=60)
    with response,path.open("xb") as output:
        while block:=response.read(1<<20):output.write(block)
    require(pin(path)==identity["zip"],"complete fixed artifact ZIP identity")
def extract(identity,root):
    require(not root.exists(),"fresh dependency root")
    root.mkdir(parents=True)
    archive=root/"artifact.zip";download(identity,archive)
    with zipfile.ZipFile(archive) as z:
        require(z.namelist()==list(dict.fromkeys(z.namelist())) and set(z.namelist())==
            {"evidence.tar.gz","FILES.json","ARCHIVE.json"} and z.testzip() is None,"complete ZIP members")
        for name in z.namelist():
            with z.open(name) as incoming,(root/name).open("xb") as output:
                while block:=incoming.read(1<<20):output.write(block)
    require(pin(root/"evidence.tar.gz")==identity["archive"],"complete TAR identity")
    index=decode((root/"FILES.json").read_bytes());report=decode((root/"ARCHIVE.json").read_bytes())
    require(report["archive"]==identity["archive"] and report["files"]==identity["files"]
        and report["logical_bytes"]==identity["logical_bytes"],"original full archive receipt")
    wanted={r["path"]:r for r in index["files"]}
    require(len(wanted)==len(index["files"])==identity["files"],"full archive file count")
    seen=set()
    with tarfile.open(root/"evidence.tar.gz","r:gz") as tar:
        for member in tar:
            name=PurePosixPath(member.name)
            require(member.isfile() and member.name in wanted and member.name not in seen
                and not name.is_absolute() and ".." not in name.parts and name.as_posix()==member.name,
                "complete archive ordinary member/path set")
            row=wanted[member.name];target=root/"extracted"/member.name
            target.parent.mkdir(parents=True,exist_ok=True)
            with tar.extractfile(member) as incoming,target.open("xb") as output:
                digest=hashlib.sha256()
                while block:=incoming.read(1<<20):digest.update(block);output.write(block)
            target.chmod(member.mode)
            require(member.size==row["bytes"] and member.mode==row["mode"] and digest.hexdigest()==row["sha256"],
                "complete archive member bytes/mode")
            seen.add(member.name)
    require(seen==set(wanted) and sum(r["bytes"] for r in wanted.values())==identity["logical_bytes"],
        "complete archive coverage")
    return root/"extracted"
def read_graph(extracted):
    capture=extracted/"capture";build=capture/"native-build";source=capture/"composition/source"
    report=decode((build/"BUILD.json").read_bytes())
    require(report["status"]=="FRESH_COMBINED_PUBLICATION123_BUILD_PASS"
        and report["direct_fresh_hia_images"]==115 and report["packed_fresh_hia_images"]==8
        and report["source_files"]==486 and report["compiler_commit"]=="d3e2c90173cf733e42b299d0c4274df4b593a12f",
        "actual fresh graph receipt")
    for row in report["processes"]:require(row["status"]=="PASS" and row["returncode"]==0,"actual packed graph builds")
    binding=source/"native/runtime_mcp_sources.json"
    require(pin(binding)==GRAPH["binding"],"complete graph source binding")
    entries=decode(binding.read_bytes())["sources"]
    require({p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}==
        set(entries)|{"native/runtime_mcp_sources.json"} and len(entries)==485,"whole graph source closure")
    for name,expected in entries.items():require(pin(source/name)==expected,"graph source "+name)
    direct=None;paths={}
    for role,expected in ROLES.items():
        actual=report["roles"][role]
        require(actual==expected,"frozen role build receipt")
        manifest=build/Path(actual["manifest"]).relative_to(OLD_GRAPH)
        require(pin(manifest)["sha256"]==expected["manifest_sha256"],"actual role manifest")
        row=decode(manifest.read_bytes());binary=manifest.parent/row["elf"]
        require(row["physical_images"]==116 and row["runtime_hia_images"]==123 and len(row["members"])==115,
            "actual direct and packed HIA inventory")
        binary_pin=dict(bytes=expected["binary_bytes"],sha256=expected["binary_sha256"])
        require(pin(binary)==binary_pin and binary_pin==dict(bytes=row["elf_bytes"],sha256=row["elf_sha256"]),
            "actual final executable bytes")
        members={}
        for member in row["members"]:
            require(member["fresh_compile"] is (role=="public"),"fresh versus same-CI reuse")
            leaf=build/Path(member["manifest"]).relative_to(OLD_GRAPH)
            require(pin(leaf)["sha256"]==member["manifest_sha256"],"actual complete leaf manifest")
            model=decode(leaf.read_bytes())
            require((leaf.parent/model["source"]).read_bytes()==(source/member["source"]).read_bytes(),
                "compiled leaf source")
            require(pin(leaf.parent/model["image"])==dict(bytes=member["image_bytes"],sha256=member["image_sha256"]),
                "compiled leaf image")
            members[member["name"]]=(member["source_sha256"],member["image_sha256"],member["image_bytes"],member["buffer_profile"])
        require(len(members)==115,"unique direct members")
        if direct is None:direct=members
        else:require(direct==members,"observation entry changed HIA bytes")
        paths[role]=str(binary)
    return paths,dict(status="COMPLETE_FRESH_PUBLIC123_GRAPH_READ_PASS",source_files=486,hia_images=123,
        physical_images=116,direct_fresh=115,packed_fresh=8,source_binding=GRAPH["binding"],
        roles={r:dict(manifest_sha256=v["manifest_sha256"],binary=dict(bytes=v["binary_bytes"],sha256=v["binary_sha256"]))
            for r,v in ROLES.items()})

def read_reference(extracted):
    capture=extracted/"capture";source=extracted/"recipe-source";reference=source/"reference"
    report=decode((capture/"BUILD.json").read_bytes())
    require(report["status"]=="FRESH_CURRENT_PUBLIC_PUBLISHER_REFERENCE_BUILD_PASS"
        and report["original_spans"]==120 and report["registry_crates"]==86 and report["registry_files"]==4401
        and report["source_files"]==46 and report["qualification"]=="NOT_RUN","fresh actual SDK reference receipt")
    spec=importlib.util.spec_from_file_location("publisher_actual_reference_verify",source/"recipe/verify_reference.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    source_proof=module.verify(reference)
    require(source_proof==report["source_proof"],"all120 exact source spans and complete wrapper")
    frozen=decode((capture/"source-closure.json").read_bytes())
    require(frozen=={p.relative_to(reference).as_posix():pin(p) for p in reference.rglob("*") if p.is_file()},
        "all compiled reference source files")
    original_root=Path("/home/runner/work/_temp/text-publication-public-reference")
    binary=capture/Path(report["binary"]).relative_to(original_root)
    require(pin(binary)==REFERENCE["binary"]=={k:report[k] for k in ("bytes","sha256")},"actual reference ELF")
    processes=decode((capture/"processes.json").read_bytes())
    require([r["name"] for r in processes]==["rustc-version","cargo-version","cargo-fetch","cargo-metadata","cargo-build"],
        "fresh reference processes")
    for row in processes:
        require(row["exit_code"]==0 and row["timed_out"] is False and row["timeout_seconds"]==180
            and 0<=row["elapsed_seconds"]<180,"actual original build limits and outcomes")
        for stream in ("stdout","stderr"):
            require(pin(capture/row[stream]["path"])=={k:row[stream][k] for k in ("bytes","sha256")},
                "actual original build complete streams")
    require((capture/"rustc-version.stdout").read_bytes()==b"rustc 1.95.0 (59807616e 2026-04-14)\n","exact Rust version")
    locked={(p["name"],p["version"]):p for p in tomllib.loads((reference/"target/Cargo.lock").read_text())["package"]
        if "source" in p}
    registry=decode((capture/"registry-sources.json").read_bytes())
    require(len(registry)==86 and sum(len(p["files"]) for p in registry)==4401,"complete target registry")
    for package in registry:
        key=package["name"],package["version"];require(key in locked,"registry package target pin")
        name=package["name"]+"-"+package["version"]
        crate=capture/"registry-archives"/(name+".crate")
        require(pin(crate)["sha256"]==package["checksum"]==locked[key]["checksum"],"target lock crate checksum")
        seen=set()
        with tarfile.open(crate,"r:gz") as tar:
            for member in tar:
                path=PurePosixPath(member.name)
                require(path.parts[0]==name and ".." not in path.parts,"registry archive canonical path")
                if member.isdir():continue
                require(member.isfile(),"ordinary original registry source")
                relative=PurePosixPath(*path.parts[1:]).as_posix()
                require(relative in package["files"] and relative not in seen,"registry exact file set")
                actual=(capture/"registry-source"/name/relative).read_bytes()
                require(dict(bytes=len(actual),sha256=sha(actual))==package["files"][relative]
                    and tar.extractfile(member).read()==actual,"complete original registry bytes")
                seen.add(relative)
        require(seen==set(package["files"]),"registry source coverage")
    return str(binary),dict(status="COMPLETE_CURRENT_PUBLIC_REFERENCE_READ_PASS",source_files=46,
        original_spans=120,target_files=17,registry_crates=86,registry_files=4401,
        actual_sdk_serve=True,actual_tool_call_context=True,actual_async_method_adapter=True,
        binary=REFERENCE["binary"],reference_source_manifest=pin(reference/"source_manifest.json"))
def verify_receipt(value):
    require(value["schema"]=="hepta.runtime.publication.dependencies.v1"
        and value["graph_identity"]==GRAPH and value["reference_identity"]==REFERENCE,
        "exact graph and reference artifact identities")
    require(value["carrier_binary_pin"]==dict(bytes=ROLES["filesystem"]["binary_bytes"],sha256=ROLES["filesystem"]["binary_sha256"])
        and value["stdio_binary_pin"]==dict(bytes=ROLES["public"]["binary_bytes"],sha256=ROLES["public"]["binary_sha256"])
        and value["original_binary_pin"]==REFERENCE["binary"],"actual execution binary pins")
    for key in ("filesystem_binary","public_binary","original_binary"):
        require(type(value[key]) is str and Path(value[key]).is_absolute(),"recorded actual binary path")
    g=value["graph_review"];r=value["reference_review"]
    require(g["status"]=="COMPLETE_FRESH_PUBLIC123_GRAPH_READ_PASS" and g["source_files"]==486
        and g["hia_images"]==123 and g["physical_images"]==116 and g["direct_fresh"]==115 and g["packed_fresh"]==8
        and g["source_binding"]==GRAPH["binding"],"complete actual graph review")
    require(g["roles"]=={role:dict(manifest_sha256=row["manifest_sha256"],
        binary=dict(bytes=row["binary_bytes"],sha256=row["binary_sha256"])) for role,row in ROLES.items()},
        "complete actual entry identities")
    require(r["status"]=="COMPLETE_CURRENT_PUBLIC_REFERENCE_READ_PASS" and r["source_files"]==46
        and r["original_spans"]==120 and r["registry_crates"]==86 and r["registry_files"]==4401
        and r["target_files"]==17 and r["binary"]==REFERENCE["binary"]
        and r["actual_sdk_serve"] is r["actual_tool_call_context"] is r["actual_async_method_adapter"] is True,
        "complete actual original review")
    require(value["executed_hia"] is value["executed_rust"] is value["reference_recompiled"] is False,
        "byte-only dependency reuse scope")
    return dict(graph_source=GRAPH["commit"],reference_source=REFERENCE["commit"],
        graph_run=GRAPH["run"],reference_run=REFERENCE["run"])
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",required=True,type=Path)
    a=p.parse_args();require(not a.output.exists(),"fresh dependency root");a.output.mkdir(parents=True)
    graph=extract(GRAPH,a.output/"graph")
    paths,gproof=read_graph(graph)
    reference=extract(REFERENCE,a.output/"reference")
    binary,rproof=read_reference(reference)
    value=dict(schema="hepta.runtime.publication.dependencies.v1",graph_identity=GRAPH,reference_identity=REFERENCE,
        filesystem_binary=paths["filesystem"],public_binary=paths["public"],original_binary=binary,
        carrier_binary_pin=dict(bytes=ROLES["filesystem"]["binary_bytes"],sha256=ROLES["filesystem"]["binary_sha256"]),
        stdio_binary_pin=dict(bytes=ROLES["public"]["binary_bytes"],sha256=ROLES["public"]["binary_sha256"]),
        original_binary_pin=REFERENCE["binary"],graph_review=gproof,reference_review=rproof,
        executed_hia=False,executed_rust=False,reference_recompiled=False)
    verify_receipt(value)
    (a.output/"DEPENDENCIES.json").write_bytes(canonical(value))
    print(json.dumps(dict(status="COMPLETE_PUBLIC_DEPENDENCIES_READ_PASS",
        graph=gproof,reference=rproof),sort_keys=True))
if __name__=="__main__":main()
