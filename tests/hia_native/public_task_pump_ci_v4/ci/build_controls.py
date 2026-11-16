"""Four physical evidence mutations, reread without executing a native image."""
from pathlib import Path
import argparse
import json
import shutil
import stat
import sys
import traceback
sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import files, pin, put, require
from read_build import prepare, verify_build

CASES = (
    ("compiler-output-tail","production/modules/task-pump-owner/module.output.bin","tail"),
    ("fresh-member-claim","production/task-pump/manifest.json","fresh"),
    ("complete-pack-workspace","journal/task-pump/pack.workspace.bin","tail"),
    ("packed-capability-byte","port/build-v3/bellman-port-packed.elf","tail"),
)

def build_inventory(build):
    result={}
    for name in ("worker","port","production","journal","trace"):
        for relative,row in files(build/name).items():
            result[name+"/"+relative]=row
    for name in ("BUILD_ORIGIN.json","same-ci-members.json"):
        result[name]=pin(build/name)
    return result

def mutation(before,kind):
    if kind=="tail":
        require(bool(before),"empty mutation source")
        return before[:-1]+bytes([before[-1]^1])
    data=json.loads(before)
    require(data["members"][0]["fresh_compile"] is True,"fresh source member differs")
    data["members"][0]["fresh_compile"]=False
    return (json.dumps(data,sort_keys=True,indent=2)+"\n").encode()

def rejection(package,clone,manifest_sha256):
    try:
        verify_build(package,clone,manifest_sha256)
    except (ValueError,AssertionError) as error:
        return {"type":type(error).__name__,"message":str(error)}
    raise ValueError("physical evidence mutation was accepted")

def verify_controls(package,build,manifest_sha256):
    control=build/"reader-controls"
    declared=json.loads((control/"source-inventory.json").read_bytes())
    require(declared and all(not n.startswith("reader-controls/") for n in declared),"control source closure differs")
    original=build_inventory(build)
    require(original==declared,"original build changed during controls")
    result=[]
    for name,relative,kind in CASES:
        case=control/name
        clone=case/"tree"
        wanted=mutation((build/relative).read_bytes(),kind)
        actual=files(clone)
        require(set(actual)==set(declared),"control clone source file set differs")
        expected=dict(declared)
        expected[relative]={"bytes":len(wanted),"sha256":__import__("hashlib").sha256(wanted).hexdigest()}
        require(actual==expected and (clone/relative).read_bytes()==wanted,"control physical mutation differs")
        failure=rejection(package,clone,manifest_sha256)
        recorded=json.loads((case/"rejection.json").read_bytes())
        require(recorded=={"case":name,"changed_path":relative,"before":declared[relative],
            "after":expected[relative],"reader_rejection":failure,"native_or_rust_executed":False},
            "actual control rejection differs")
        result.append(recorded)
    require({p.name for p in control.iterdir()}=={"source-inventory.json","report.json",*(x[0] for x in CASES)},
            "control artifact set differs")
    report={"status":"PHYSICAL_GRAPH_READER_CONTROLS_PASS","refusals":len(result),
        "cases":result,"native_or_rust_executed":False,"files_written":False}
    require(json.loads((control/"report.json").read_bytes())==report,"control report differs")
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("package","build"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--manifest-sha256",required=True)
    a=p.parse_args()
    package,build=a.package.resolve(strict=True),a.build.resolve(strict=True)
    prepare(package)
    verify_build(package,build,a.manifest_sha256)
    inventory=build_inventory(build)
    control=build/"reader-controls"
    require(not control.exists(),"control capture already exists")
    control.mkdir()
    put(control/"source-inventory.json",inventory)
    results=[]
    for name,relative,kind in CASES:
        case=control/name
        clone=case/"tree"
        clone.mkdir(parents=True)
        for file in inventory:
            target=clone/file
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(build/file,target)
            target.chmod(stat.S_IMODE((build/file).stat().st_mode))
        changed=clone/relative
        changed.write_bytes(mutation(changed.read_bytes(),kind))
        failure=rejection(package,clone,a.manifest_sha256)
        row={"case":name,"changed_path":relative,"before":inventory[relative],
            "after":pin(changed),"reader_rejection":failure,"native_or_rust_executed":False}
        put(case/"rejection.json",row)
        results.append(row)
    report={"status":"PHYSICAL_GRAPH_READER_CONTROLS_PASS","refusals":len(results),
        "cases":results,"native_or_rust_executed":False,"files_written":False}
    put(control/"report.json",report)
    require(verify_controls(package,build,a.manifest_sha256)==report,"control independent reread differs")
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
