"""Physical evidence refusals and relocated pair reads; no target execution."""
from pathlib import Path
import argparse,json,os,shutil,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
source=Path(os.environ["WAIT_SOURCE"]).resolve(strict=True)
sys.path[:0]=[str(source),str(source/"build_reader"),str(HERE)]
import read_capture_fixed as read_capture
import read_only_guard as guard
from capture_common import file_pin
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
def main():
    p=argparse.ArgumentParser();p.add_argument("--capture",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    capture=a.capture.resolve(strict=True);output=a.output.absolute();assert not output.exists();output.mkdir(parents=True)
    inputs=json.loads((capture/"INPUTS_READY.json").read_bytes())
    cases=[("public-wire","native/000/process/stdout.bin.gz"),("accepted-input","native/000/process/stdin.bin.gz"),("private-state","native/000/process/controls/0001.output.bin.gz"),("host-trace","native/000/process/host-trace.bin.gz"),("binary","native/tool-runtime.bin"),("case-file","native/000/CASE.json"),("original-wire","original/000/process/stdout.bin.gz"),("domain","native/DOMAIN.json"),("relocated-a",None),("relocated-b",None)]
    rows=[]
    for name,target in cases:
        working=output.parent/("pair-control-"+name);assert not working.exists()
        shutil.copytree(capture,working,copy_function=os.link)
        proof=output/name;proof.mkdir()
        mutation=None
        if target is not None:
            path=working/target;before=path.read_bytes();assert before
            after=bytes([before[0]^1])+before[1:];mode=path.stat().st_mode&0o777
            path.unlink();path.write_bytes(after);os.chmod(path,mode)
            (proof/"before.bin").write_bytes(before);(proof/"after.bin").write_bytes(after)
            mutation={"path":target,"before":file_pin(proof/"before.bin"),"after":file_pin(proof/"after.bin"),"mode":mode}
        def read():
            try:
                pair=[read_capture.read(working/side,side,{k:inputs[side][k] for k in ("bytes","sha256")}) for side in ("original","native")]
                value=read_capture.compare(*pair)
            except (ValueError,AssertionError,KeyError,UnicodeDecodeError) as error:
                if target is None:raise
                return {"status":"PHYSICAL_EVIDENCE_REJECTED","error":str(error),"type":type(error).__name__}
            assert target is None,"reader accepted physically corrupted evidence"
            return value
        checked=guard.guarded(read,roots=[working,HERE,source],foreign_path=Path("/dev/null"))
        put(proof/"READ.json",checked);put(proof/"MUTATION.json",mutation)
        files=0
        for path in sorted(working.rglob("*")):
            if not path.is_file():continue
            relative=path.relative_to(working).as_posix()
            wanted=proof/"after.bin" if relative==target else capture/relative
            assert path.read_bytes()==wanted.read_bytes()
            if relative!=target:assert path.stat().st_mode&0o777==wanted.stat().st_mode&0o777
            files+=1
        put(proof/"RETIREMENT.json",{"all_files":files,"complete_bytes_compared":True,"all_unchanged_modes_compared":True,"mutation_mode_retained":mutation["mode"] if mutation else None})
        shutil.rmtree(working)
        rows.append({"name":name,"status":checked["evidence"]["status"],"guard_probes":len(checked["probes"]),"target":target,"complete_files":files})
    result={"status":"EIGHT_PHYSICAL_CONTROLS_TWO_RELOCATIONS_PASS","cases":rows,"application_executions":0};put(output/"CONTROLS.json",result)
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
