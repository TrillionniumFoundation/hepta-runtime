"""Read every target crate archive and every actual vendored implementation byte."""
from pathlib import Path
import io,tarfile,tomllib
from common import ROOT,read,loads,pin,require,files
from reader_common import ROOT as READER_ROOT
def verify(root):
    packages=[p for p in tomllib.loads(read(ROOT/"reference/Cargo.lock").decode())["package"]if"source"in p]
    plan=loads(read(ROOT/"reference/REGISTRY_PLAN.json"));observed=loads(read(READER_ROOT/"REGISTRY-CARGO-METADATA.json"))
    target={p["name"]+"-"+p["version"]:p for p in plan["crates"]}
    known={r["name"]:r for r in observed};names={p["name"]+"-"+p["version"]for p in packages}
    require(len(names)==len(packages)==22 and names==set(target)==set(known),"entire actual locked target feature closure")
    require({p.name for p in(root/"vendor").iterdir()}==names and
            {p.name for p in(root/"crates").iterdir()}=={n+".crate"for n in names},"whole archive/vendor package domain")
    count=total=0;metadata={}
    for p in packages:
        name=p["name"]+"-"+p["version"];raw=read(root/"crates"/(name+".crate"))
        require(pin(raw)==target[name]["archive"]==known[name]["archive"]and pin(raw)["sha256"]==p["checksum"],
                "actual complete target crate/checksum")
        checksum=loads(read(root/"vendor"/name/".cargo-checksum.json"))
        require(set(checksum)=={"files","package"}and checksum["package"]==p["checksum"],"actual Cargo generated metadata")
        require(pin(read(root/"vendor"/name/".cargo-checksum.json"))==known[name]["added"][".cargo-checksum.json"],
                "complete actual generated metadata bytes")
        rows={};seen=set();omitted={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz")as tf:
            for entry in tf:
                if entry.isdir():continue
                require(entry.isfile()and entry.name.startswith(name+"/"),"ordinary locked implementation member")
                rel=entry.name[len(name)+1:]
                require(rel and ".."not in Path(rel).parts and rel not in seen,"unique complete relative original source")
                seen.add(rel);body=tf.extractfile(entry).read();require(len(body)==entry.size,"whole original member")
                if rel in known[name]["omitted"]:
                    require(pin(body)==known[name]["omitted"][rel]and Path(rel).name in(".gitignore",".gitattributes"),
                            "only exact Cargo Git metadata omission, complete bytes still retained")
                    omitted[rel]=pin(body)
                else:
                    require(read(root/"vendor"/name/rel)==body,"all complete original implementation bytes")
                    rows[rel]=dict(**pin(body),mode=entry.mode&0o777)
                count+=1;total+=len(body)
        require(len(seen)==known[name]["members"]and omitted==known[name]["omitted"]and not known[name]["different"],
                "entire exact archive source and known Cargo metadata")
        require(files(root/"vendor"/name,(".cargo-checksum.json",))==rows and
                checksum["files"]=={k:r["sha256"]for k,r in rows.items()},"no extra/missing/changed vendor source or mode")
        metadata[name]=omitted
    return dict(packages=22,source_files=count,source_bytes=total,retained_nonimplementation_metadata=metadata,
                inspection_head="48d5cf17e2c0a5a960f9142d5748afbaae24216f",inspection_run=44114666930)
