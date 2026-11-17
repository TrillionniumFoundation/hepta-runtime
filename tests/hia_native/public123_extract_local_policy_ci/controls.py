"""Six physical corruptions and one full relocation, never application execution."""
from pathlib import Path
import argparse,json,os,shutil,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from read_primitives import *
import read_graph,read_successor,read_only_guard as guard
HERE=Path(__file__).resolve().parent
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
def main():
    p=argparse.ArgumentParser()
    for name in ("retained","fixture","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();retained=a.retained.resolve(strict=True);fixture=a.fixture.resolve(strict=True)
    require(not a.output.exists(),"fresh controls");a.output.mkdir(parents=True)
    modules=read_graph.prepare(retained);cases=[("pack-output","fixture/build-fixture/policy-fixture/pack.output.bin","complete actual packed output differs"),("new-compiled-source","fixture/build-public/modules/policy-public-extract-gateway/policy-public-extract-gateway.hepta","compiled source copy differs"),("retained-compiled-source","retained/capture/native-build/build-public/modules/publication-public-extract-body/publication-public-extract-body.hepta","compiled source copy differs"),("fixed-table","fixture/build-fixture/policy-fixture/manifest.json","frozen new entry identity"),("production-source","fixture/source/native/extract_gateway.hepta","successor source bytes"),("fixture-source","fixture/fixture.S","complete private fixture source/inverse"),("relocated",None,None)]
    rows=[]
    for name,relative,needle in cases:
        working=a.output.parent/("control-working-"+name);require(not working.exists(),"fresh physical clone")
        shutil.copytree(retained,working/"retained",copy_function=os.link)
        shutil.copytree(fixture,working/"fixture",copy_function=os.link)
        read_graph.LOADED[str((working/"retained").resolve())]=modules
        evidence=a.output/name;evidence.mkdir()
        mutation=None
        if relative is not None:
            target=working/relative;before=raw(target)
            if name=="fixed-table":
                value=json.loads(before);value["extra_table"][59]="publisher_gateway";after=(json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
            elif name=="pack-output":after=before[:-1]+bytes([before[-1]^1])
            else:after=before+b"\n"
            mode=target.stat().st_mode&0o777;target.unlink();target.write_bytes(after);os.chmod(target,mode)
            (evidence/"before.bin").write_bytes(before);(evidence/"after.bin").write_bytes(after)
            mutation={"path":relative,"before":{"bytes":len(before),"sha256":sha(before)},"after":{"bytes":len(after),"sha256":sha(after)},"mode":mode}
        def operation():
            try:
                value=read_successor.verify(working/"retained",working/"fixture")
            except (ValueError,AssertionError,KeyError) as error:
                require(needle is not None and needle in str(error),"physical control refused for an unrelated reason: "+repr(error))
                return {"status":"TARGETED_PHYSICAL_REFUSAL","error":str(error)}
            require(needle is None,"reader accepted physically corrupted evidence")
            return value
        proof=guard.guarded(operation,roots=[working/"retained",working/"fixture",HERE],foreign_path=Path("/dev/null"))
        put(evidence/"READ.json",proof);put(evidence/"MUTATION.json",mutation)
        # Retire only complete duplicate files or the two separately retained
        # exact mutation versions. The producer archives remain separately bound.
        count=0
        for pth in sorted(working.rglob("*")):
            if not pth.is_file():continue
            rel=pth.relative_to(working).as_posix()
            if rel==relative:require(raw(pth)==raw(evidence/"after.bin"),"retained mutation byte identity")
            else:
                first,rest=rel.split("/",1);origin=(retained if first=="retained" else fixture)/rest
                require(raw(pth)==raw(origin) and pth.stat().st_mode&0o777==origin.stat().st_mode&0o777,"complete duplicate retirement bytes/mode")
            count+=1
        put(evidence/"RETIREMENT.json",{"complete_files":count,"all_bytes_and_modes_verified":True,"mutation_versions_retained":relative is not None,"producer_artifacts_retained":True})
        shutil.rmtree(working)
        rows.append({"name":name,"target":relative,"status":proof["evidence"]["status"],"guard_probes":len(proof["probes"]),"physical_file":mutation,"complete_duplicate_files_retired":count})
    result={"status":"SIX_PHYSICAL_CONTROLS_AND_RELOCATION_PASS","cases":rows,"native_or_rust_executions":0}
    put(a.output/"CONTROLS.json",result);print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
