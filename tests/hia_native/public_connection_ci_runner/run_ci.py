"""Fresh public83 via its default entry, current SDK originals, and complete readers."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys,time,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from check_source import check,check_runner
from verify_complete import FALSE_FLAGS
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--source",type=Path,required=True)
    for name in ("sdk-source","hepta","rust-bin","get-info-reference","output"):
        p.add_argument("--"+name,type=Path)
    p.add_argument("--check-only",action="store_true");a=p.parse_args()
    source=a.source.resolve(strict=True);closure=check(source);runner=check_runner(HERE)
    if a.check_only:
        print(json.dumps(dict(status="SOURCE_CLOSURE_PASS",**closure,runner=runner,native_or_rust_executed=False),sort_keys=True));return
    assert os.environ.get("CI")=="true","Fresh Rust is executed only in CI."
    assert all(getattr(a,name) for name in ("sdk_source","hepta","rust_bin","get_info_reference","output"))
    reference=a.get_info_reference.resolve(strict=True);raw=reference.read_bytes()
    assert len(raw)==1236951 and SHA(raw)=="c9ff4c9282e406de911119c2287093165d3829c333be43da06ac14f75edf295d"
    output=a.output.absolute();assert not output.exists() and not output.is_relative_to(source)
    output.mkdir(parents=True);(output/"processes").mkdir()
    report=dict(schema="hepta.public83.connection.recipe.v1",status="RUNNING",processes=[],
        source_manifest_sha256=closure["source_manifest_sha256"],fresh_retained_62=False,fresh_public_83=False,
        fresh_exact_transport_original=False,fresh_exact_handshake_original=False,
        existing_binary_inputs=False,rust_executed=False,**{name:False for name in FALSE_FLAGS})
    started=time.monotonic()
    def checkpoint():report["elapsed_seconds"]=time.monotonic()-started;put(output/"RECIPE.json",report)
    def run(label,script,args):
        command=[sys.executable,"-I","-B",str(script),*map(str,args)];begin=time.monotonic()
        with (output/"processes"/(label+".stdout")).open("xb") as out,(output/"processes"/(label+".stderr")).open("xb") as err:
            proc=subprocess.Popen(command,stdout=out,stderr=err);code=proc.wait()
        row=dict(label=label,command=command,exit_code=code,elapsed_seconds=time.monotonic()-begin,outer_timeout_seconds=None)
        for stream in ("stdout","stderr"):
            raw=(output/"processes"/(label+"."+stream)).read_bytes();row[stream]=dict(bytes=len(raw),sha256=SHA(raw))
        report["processes"].append(row);checkpoint();assert code==0,label
    checkpoint()
    try:
        run("install-default-entry",HERE/"install_entrypoint.py",["--source",source,"--output",output/"graph-source"])
        run("fresh-retained62",source/"transport-reference/drivers/build_retained_eight.py",
            ["--sdk-source",a.sdk_source,"--hepta",a.hepta,"--output",output/"retained-eight"])
        baseline=json.loads((output/"retained-eight/BUILD.json").read_bytes())
        assert baseline["fresh_members"]==62 and baseline["existing_binary_inputs"] is False
        report["fresh_retained_62"]=True;checkpoint()
        run("fresh-public83",output/"graph-source/scripts/hia_native_runtime_mcp_build.py",
            ["--hepta",a.hepta,"--output",output/"public","--bootstrap",output/"retained-eight/build/bootstrap"])
        public=json.loads((output/"public/BUILD.json").read_bytes())
        assert public["fresh_member_compiles"]==83 and public["checked_reused_members"]==0
        assert public["default_public_entrypoint"] is True
        report["fresh_public_83"]=True;checkpoint()
        run("normal-corpus",source/"drivers/transport_cases.py",["--output",output/"transport-inputs"])
        run("native-framing24",source/"drivers/capture_transport_native.py",
            ["--build",output/"public","--cases",output/"transport-inputs","--output",output/"native-framing"])
        run("fresh-original28",source/"transport-reference/drivers/run_transport_reference.py",
            ["--source",source/"transport-reference","--cases",output/"transport-inputs","--native",output/"native-framing",
             "--rust-bin",a.rust_bin,"--output",output/"transport-reference"])
        assert json.loads((output/"transport-reference/SUMMARY.json").read_bytes())["status"]=="ACTUAL_TARGET_TRANSPORT_REFERENCE_PASS"
        report.update(fresh_exact_transport_original=True,rust_executed=True);checkpoint()
        run("fresh-original54",source/"handshake-reference/scripts/run_reference.py",
            ["--source",source/"handshake-reference","--rust-bin",a.rust_bin,"--output",output/"handshake-reference"])
        assert json.loads((output/"handshake-reference/SUMMARY.json").read_bytes())["status"]=="PASS"
        report["fresh_exact_handshake_original"]=True;checkpoint()
        run("native-handshake54",source/"drivers/capture_handshake.py",
            ["--source",source/"handshake-reference","--build",output/"public","--output",output/"native-handshake"])
        run("retained-public90",source/"drivers/qualify_public.py",
            ["--source",output/"graph-source","--manifest",public["manifest"],"--baseline-elf",baseline["elf"],
             "--get-info-reference",reference,"--output",output/"public-loop"])
        run("readonly-complete",HERE/"verify_complete.py",["--source",source,"--run",output,"--require-fresh"])
        gate=json.loads((output/"processes/readonly-complete.stdout").read_bytes())
        assert gate["status"]=="READONLY_PUBLIC83_HANDSHAKE324_PUBLIC90_TRANSPORT24_PASS"
        put(output/"verification.json",gate);assert check(source)==closure and check_runner(HERE)==runner
        report.update(status="PASS",sessions=54,handshake_responses=324,serial_public_wire_cases=24,
            codec_eof_reference_only_cases=4,public_counts=gate["public"]["counts"],candidate_elf_sha256=gate["candidate_elf_sha256"])
    except BaseException:report.update(status="FAIL",failure=traceback.format_exc());raise
    finally:checkpoint()
    print(json.dumps({k:v for k,v in report.items() if k!="processes"},sort_keys=True))
if __name__=="__main__":main()
