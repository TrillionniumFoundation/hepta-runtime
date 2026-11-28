#!/usr/bin/env python3
"""Build-artifact reread plus a frozen, separately counted actual kernel observer domain."""
from pathlib import Path
import argparse,ast,json,os,platform,signal,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from process import Recorder,environment
def checked(expected):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"frozen observer preflight source differs")
    return source_evidence(ROOT)
def source_check():
    require(platform.machine()=="x86_64"and sys.version_info[:3]==(3,12,3),"fixed Linux x86-64 CPython 3.12.3")
    executable=Path(sys.executable).resolve(strict=True)
    require(pin(executable)==dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"),
        "qualified actual original interpreter bytes")
    files=[]
    for path in sorted(ROOT.rglob("*.py")):
        raw=path.read_bytes();compile(raw,str(path),"exec",flags=ast.PyCF_ONLY_AST);files.append(path.relative_to(ROOT).as_posix())
    return dict(status="SOURCE_ONLY_PASS",python=pin(executable),python_version=list(sys.version_info[:3]),python_sources=files,
        source=source_evidence(ROOT),original_write_application_calls=0,target_hia_application_calls=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["run","read","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--output",type=Path)
    p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    identity=checked(a.source_manifest_sha256);work=a.work.absolute();work.mkdir(parents=True,exist_ok=True)
    if a.stage=="read":
        from readonly import guarded
        from read_trace_probe import verify
        domain=decode((ROOT/"PROBE_DOMAIN.json").read_bytes())
        result=guarded(lambda:dict(status="FOUR_ACTUAL_KERNEL_OBSERVER_PROBES_PASS",
            probes=[verify(ROOT,work/"probes"/str(q["id"]),q)for q in domain["cases"]],
            original_write_application_calls=0,target_hia_application_calls=0,observer_probe_calls=4),
            roots=[ROOT,work/"probes"])
        print(encoded(result).decode(),end="");return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh preflight export")
        a.output.mkdir(parents=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("full-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        (a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,process=row,archive=decode(raw))))
        print(raw.decode(),end="");return
    env,binding=environment(os.environ);rec=Recorder(ROOT,work/"processes",env)
    try:
        source=source_check();(work/"SOURCE_CHECK.json").write_bytes(encoded(source))
        for stage in("fetch","unpack","read"):
            raw,row=rec.run("build-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/build_reuse.py",stage,
                "--source",ROOT,"--work",work],timeout=180)
            (work/("BUILD_"+stage.upper()+".json")).write_bytes(raw)
        domain=decode((ROOT/"PROBE_DOMAIN.json").read_bytes())
        for q in domain["cases"]:
            raw,row=rec.run("probe-"+str(q["id"]),[sys.executable,"-I","-S","-B",ROOT/"scripts/trace_probe_capture.py",
                "--source",ROOT,"--output",work/"probes"/str(q["id"]),"--case",str(q["id"])],timeout=60)
        raw,row=rec.run("read-probes",[sys.executable,"-I","-S","-B",Path(__file__).resolve(),"read",
            "--work",work,"--source-manifest-sha256",a.source_manifest_sha256],timeout=180)
        result=decode(raw);require(result["before"]==result["after"]and len(result["probes"])==11,"pure probe reader custody")
        (work/"READONLY.json").write_bytes(raw)
        final=dict(status="PASS",source=identity,source_check=source,build=decode((work/"BUILD_READ.json").read_bytes()),
            actual_probe_read=result,processes=rec.records,environment=binding,
            original_write_application_calls=0,target_hia_application_calls=0,observer_probe_calls=4)
        (work/"GATE.json").write_bytes(encoded(final));require(checked(a.source_manifest_sha256)==identity,"frozen source changed")
        print(encoded(dict(status="BUILD_REREAD_AND_FOUR_KERNEL_PROBES_PASS",target_hia_application_calls=0,
            original_write_application_calls=0,observer_probe_calls=4,
            build_executable=dict(bytes=1622016,sha256="91564f7879d7c83af62adf9dd8d8654ea48c430a20883362e4e3ef538cbcf5ba"),
            probes=result["evidence"]["probes"],guards=11)).decode(),end="")
    except BaseException as e:
        (work/"GATE.json").write_bytes(encoded(dict(status="FAIL",source=identity,error_type=type(e).__name__,
            message=str(e),traceback=traceback.format_exc(),processes=rec.records,
            original_write_application_calls=0,target_hia_application_calls=0,
            completed_probe_names=[q["name"]for q in rec.records if q["name"].startswith("probe-")and q["exit_code"]==0],
            replay_permitted=False)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
