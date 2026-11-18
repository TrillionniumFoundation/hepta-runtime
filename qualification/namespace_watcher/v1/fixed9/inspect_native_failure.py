"""Read the complete failed build; no assembler/HIA/Rust or semantic replay."""
import argparse,re,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import encoded,loads,read,pin,require,source
def run(prior):
    identity=source();base=prior/"complete"
    rows=loads(read(base/"run/processes/processes.json"))
    require([x["name"] for x in rows]==["source-check","fresh-owner","author-callable"],"complete actual failure process prefix")
    require([x["exit_code"] for x in rows]==[0,0,1] and not any(x["timed_out"] for x in rows),"actual compile and author failure")
    require([x["timeout_seconds"] for x in rows]==[60,900,60],"unchanged process bounds")
    for row in rows:
        for kind in ("stdout","stderr"):
            r=row[kind];require(pin(read(base/"run/processes"/r["file"]))=={k:r[k] for k in ("bytes","sha256")},"full original process stream")
    owner=loads(read(base/"run/build/OWNER_BUILD.json"))
    require(owner["status"]=="PASS" and owner["module"]["image"]==loads(read(ROOT/"SOURCE_QUALIFIED.json"))["owner_image"],
        "unchanged actual HIA owner compiled before native failure")
    actual=loads(read(base/"run/authored/ASSEMBLY-PROCESSES.json"))
    require(len(actual)==4,"all original GAS tools completed")
    for i,row in enumerate(actual):
        require(row["exit_code"]==0 and row["timeout_seconds"]==60
            and row["stdout"]==pin(read(base/("run/authored/"+str(i)+".stdout")))
            and row["stderr"]==pin(read(base/("run/authored/"+str(i)+".stderr")))
            and not read(base/("run/authored/"+str(i)+".stderr")),"all complete original GAS streams")
    raw=read(base/"run/authored/2.stdout");text=raw.decode()
    relocations=re.findall(r"^\s*[0-9a-f]+\s+[0-9a-f]+\s+(R_X86_64_\S+)\s+[0-9a-f]+\s+(\S+)\s+-\s+4\s*$",text,re.M)
    wanted=Counter({("R_X86_64_PLT32","namespace_watcher_owner"):1,
        ("R_X86_64_PLT32","namespace_file_pin_adopt"):1,("R_X86_64_PLT32","namespace_file_pin_clone"):1,
        ("R_X86_64_PLT32","namespace_file_pin_release"):3})
    require(Counter(relocations)==wanted and "There are no relocations in this file." not in text,
        "exact observed six global direct-call relocations; no inferred unrelated repair")
    require(read(base/"source/authoring/namespace_watcher_callable.S.in")==read(ROOT/"previous/namespace_watcher_callable.S.in"),
        "complete original failing native source")
    print("ORIGINAL_READELF_BEGIN");print(text,end="");print("ORIGINAL_READELF_END")
    result=dict(status="EXACT_NATIVE_AUTHOR_FAILURE_READ_PASS",source_manifest_sha256=identity,
        original_failure_retained=True,readelf=pin(raw),relocations=relocations,
        original_hia_owner=owner["module"]["image"],native_or_rust_executions=0)
    print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--prior",type=Path,required=True);a=p.parse_args();run(a.prior.resolve(strict=True))
