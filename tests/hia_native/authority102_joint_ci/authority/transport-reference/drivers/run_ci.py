"""Fresh serial public81, exact current SDK framing, and retained public90 CI recipe."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess,sys,time,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_source import check,base,installed
SHA=lambda b:hashlib.sha256(b).hexdigest()
FALSE_FLAGS=("full_sdk_qualified","full_136_route_qualified","full_async_runtime_qualified",
    "service_task_or_future_lifecycle_qualified","cancellation_timing_qualified",
    "target_connection_identity_integrated","target_general_response_owner_integrated",
    "fixed_get_info_publicly_integrated","production_activated","old_path_removed","independent_cold_qualified")
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--source",required=True,type=Path)
    for name in ("base-source","sdk-source","hepta","rust-bin","output"):p.add_argument("--"+name,type=Path)
    p.add_argument("--check-only",action="store_true");a=p.parse_args()
    source=a.source.resolve(strict=True);closure=check(source)
    if a.check_only:print(json.dumps(dict(status="SOURCE_CLOSURE_PASS",**closure,native_or_rust_executed=False),sort_keys=True));return
    assert os.environ.get("CI")=="true","Full recipe executes fresh Rust only in CI."
    assert all(getattr(a,n) for n in ("base_source","sdk_source","hepta","rust_bin","output"))
    base_source=a.base_source.resolve(strict=True);base_closure=base(base_source)
    output=a.output.absolute();assert not output.exists() and not output.is_relative_to(source)
    output.mkdir(parents=True);(output/"processes").mkdir()
    shutil.copytree(base_source,output/"base-input",copy_function=shutil.copyfile)
    assert base(output/"base-input")==base_closure
    report=dict(schema="hepta.public-serial81.recipe.v1",status="RUNNING",processes=[],
        source_manifest=closure["source_manifest"],base_source_manifest=base_closure["source_manifest"],
        fresh_retained_62=False,fresh_public_81=False,existing_binary_inputs=False,
        actual_target_serial_transport_compared=False,fresh_exact_rust_built=False,rust_executed=False,
        **{k:False for k in FALSE_FLAGS})
    start=time.monotonic()
    def checkpoint():report["elapsed_seconds"]=time.monotonic()-start;put(output/"RECIPE.json",report)
    def run(label,script,args):
        command=[sys.executable,"-I","-B",str(source/"drivers"/script),*map(str,args)]
        begin=time.monotonic()
        with (output/"processes"/(label+".stdout")).open("xb") as out,(output/"processes"/(label+".stderr")).open("xb") as err:
            proc=subprocess.Popen(command,stdout=out,stderr=err);code=proc.wait()
        row=dict(label=label,command=command,exit_code=code,elapsed_seconds=time.monotonic()-begin,outer_timeout_seconds=None)
        for name in ("stdout","stderr"):
            raw=(output/"processes"/(label+"."+name)).read_bytes();row[name]=dict(bytes=len(raw),sha256=SHA(raw))
        report["processes"].append(row);checkpoint()
        assert code==0,label
    checkpoint()
    try:
        run("install-serial81","install_serial_public.py",["--base-source",output/"base-input/source","--overlay",source/"overlay","--output",output/"graph-source"])
        installed(output/"graph-source")
        run("fresh-retained62","build_retained_eight.py",["--sdk-source",a.sdk_source,"--hepta",a.hepta,"--output",output/"retained-eight"])
        baseline=json.loads((output/"retained-eight/BUILD.json").read_bytes())
        assert baseline["fresh_members"]==62 and baseline["existing_binary_inputs"] is False
        report["fresh_retained_62"]=True;checkpoint()
        run("fresh-public81","build_serial_public.py",["--source",output/"graph-source","--hepta",a.hepta,
            "--output",output/"public","--bootstrap",output/"retained-eight/build/bootstrap"])
        public=json.loads((output/"public/BUILD.json").read_bytes())
        assert public["fresh_member_compiles"]==81 and public["checked_reused_members"]==0
        report["fresh_public_81"]=True;checkpoint()
        run("normal-corpus","transport_cases.py",["--output",output/"transport-inputs"])
        run("native-framing24","capture_transport_native.py",["--build",output/"public","--cases",output/"transport-inputs","--output",output/"native-framing"])
        run("fresh-original28","run_transport_reference.py",["--source",source,"--cases",output/"transport-inputs",
            "--native",output/"native-framing","--rust-bin",a.rust_bin,"--output",output/"reference"])
        original=json.loads((output/"reference/SUMMARY.json").read_bytes())
        assert original["status"]=="ACTUAL_TARGET_TRANSPORT_REFERENCE_PASS"
        report.update(fresh_exact_rust_built=True,rust_executed=True,actual_target_serial_transport_compared=True);checkpoint()
        run("retained-public90","qualify_public81.py",["--source",output/"graph-source","--manifest",public["manifest"],
            "--baseline-elf",baseline["elf"],"--output",output/"public-loop"])
        run("readonly-complete","verify_complete.py",["--source",source,"--run",output])
        verified=json.loads((output/"processes/readonly-complete.stdout").read_bytes())
        assert verified["status"]=="READONLY_FRESH81_SERIAL_TRANSPORT_PUBLIC90_PASS"
        put(output/"verification.json",verified)
        assert check(source)==closure and base(base_source)==base_closure
        report.update(status="PASS",public_counts=verified["public_counts"],serial_public_wire_cases=24,
            codec_eof_reference_only_cases=4,original_processes=28,candidate_elf_sha256=verified["candidate_elf_sha256"])
    except BaseException:report.update(status="FAIL",failure=traceback.format_exc());raise
    finally:checkpoint()
    print(json.dumps({k:v for k,v in report.items() if k!="processes"},sort_keys=True))
if __name__=="__main__":main()
