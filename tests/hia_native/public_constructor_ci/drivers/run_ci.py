"""Fresh owned HIA80 and Rust1.95 constructor plus ordinary public9 qualification."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys, time, traceback
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()

def put(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,required=True)
    for name in ("sdk-source","hepta","rust-bin","output"):
        p.add_argument("--"+name,type=Path)
    p.add_argument("--check-only",action="store_true")
    a=p.parse_args();source=a.source.resolve(strict=True)
    sys.path.insert(0,str(source/"drivers"))
    from package_checks import verify_source
    closure=verify_source(source)
    if a.check_only:
        print(json.dumps(dict(status="SOURCE_CHECK_PASS",files=len(closure["files"]),
            source_manifest_sha256=SHA((source/"source-manifest.json").read_bytes()),
            native_or_rust_executed=False),sort_keys=True));return
    assert os.environ.get("CI")=="true","The full recipe executes Rust only in CI."
    assert a.sdk_source and a.hepta and a.rust_bin and a.output
    output=a.output.resolve()
    assert not output.exists() and not output.is_relative_to(source)
    output.mkdir(parents=True);(output/"processes").mkdir()
    processes=[];begin=time.monotonic()
    report=dict(schema="hepta.runtime.public-constructor-ci-recipe.v1",status="RUNNING",
        source_manifest_sha256=SHA((source/"source-manifest.json").read_bytes()),
        existing_binary_inputs=False,fresh_62_baseline=False,fresh_80_candidate=False,
        fresh_exact_rust_built=False,rust_executed=False,actual_target_constructor_comparison=False,
        target_original_public_handler_comparison=False,
        target_connection_identity_integrated=False,target_general_response_owner_integrated=False,
        target_async_transport_integrated=False,full_sdk_qualified=False,full_136_route_qualified=False,
        full_async_text_editor_qualified=False,scope_wide_qualified=False,
        cancellation_fence_timing_qualified=False,production_activated=False,old_path_removed=False,
        fresh_cold_qualified=False,outer_subprocess_timeout_seconds=None,
        native_call_timeout_seconds=60,original_call_timeout_seconds=60,
        reference_build_step_timeout_seconds=180,public_exchange_timeout_seconds=60)
    def save():
        report.update(processes=processes,elapsed_seconds=time.monotonic()-begin)
        put(output/"RECIPE.json",report)
    def run(label,args):
        started=time.monotonic()
        with (output/"processes"/(label+".stdout")).open("xb") as stdout, (output/"processes"/(label+".stderr")).open("xb") as stderr:
            process=subprocess.Popen([str(x) for x in args],stdout=stdout,stderr=stderr)
            code=process.wait()
        row=dict(label=label,command=[str(x) for x in args],exit_code=code,
                 elapsed_seconds=time.monotonic()-started,outer_timeout_seconds=None)
        for stream in ("stdout","stderr"):
            raw=(output/"processes"/(label+"."+stream)).read_bytes()
            row[stream]=dict(bytes=len(raw),sha256=SHA(raw))
        processes.append(row);save()
        assert code==0,label
    python=[sys.executable,"-I","-B"]
    save()
    try:
        run("fresh-retained-62",python+[source/"drivers/build_retained_eight.py",
            "--sdk-source",a.sdk_source,"--hepta",a.hepta,"--output",output/"retained-eight"])
        base=json.loads((output/"retained-eight/BUILD.json").read_bytes())
        assert base["fresh_members"]==62 and base["existing_binary_inputs"] is False
        report["fresh_62_baseline"]=True;save()
        run("fresh-public-80",python+[source/"drivers/build_public_constructor.py",
            "--source",source/"source","--hepta",a.hepta,"--output",output/"public",
            "--bootstrap",output/"retained-eight/build/bootstrap"])
        public=json.loads((output/"public/BUILD.json").read_bytes())
        assert public["fresh_member_compiles"]==80 and public["checked_reused_members"]==0
        report["fresh_80_candidate"]=True;save()
        run("fresh-constructor-components",python+[source/"source/scripts/build_constructor.py",
            "--source",source/"source","--hepta",a.hepta,"--output",output/"component",
            "--bootstrap",output/"public/build/bootstrap"])
        run("native-constructor-65",python+[source/"source/scripts/qualify_constructor_native.py",
            "--source",source/"source","--build",output/"component",
            "--output",output/"component-native","--profile","wide"])
        run("fresh-original-constructor-65",python+[source/"drivers/run_constructor_reference.py",
            "--source",source,"--output",output/"original","--rust-bin",a.rust_bin,
            "--native-evidence",output/"component-native"])
        original=json.loads((output/"original/SUMMARY.json").read_bytes())
        assert original["status"]=="ACTUAL_TARGET_CONSTRUCTOR_PASS" and original["completed_cases"]==65
        report.update(fresh_exact_rust_built=True,rust_executed=True,actual_target_constructor_comparison=True);save()
        run("actual-public-nine",python+[source/"drivers/qualify_native_constructor_public.py",
            "--source",source/"source","--manifest",public["manifest"],
            "--baseline-elf",base["elf"],"--output",output/"public-loop"])
        run("readonly-complete",python+[source/"drivers/verify_complete.py","--source",source,"--run",output])
        verified=json.loads((output/"processes/readonly-complete.stdout").read_bytes())
        assert verified["status"]=="READONLY_FRESH80_CONSTRUCTOR_PUBLIC90_PASS"
        put(output/"verification.json",verified)
        assert verify_source(source)==closure
        report.update(status="PASS",counts=verified["public_counts"],
            candidate_elf_sha256=verified["candidate_elf_sha256"],
            actual_target_constructor_cases=verified["actual_target_rust_cases"],
            public_ordinary_nine_route_qualified=True,
            bootstrap_built_fresh_in_same_invocation=True)
    except BaseException:
        report.update(status="FAIL",failure=traceback.format_exc())
        raise
    finally:save()
    print(json.dumps(report,sort_keys=True),flush=True)

if __name__=="__main__":main()

