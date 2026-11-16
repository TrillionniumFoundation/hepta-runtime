"""CI-only fresh fixed get_info HIA build and retained-original comparison."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys, time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_source import check
FALSE_FLAGS=("full_sdk_qualified","full_async_runtime_qualified","production_activated",
             "old_path_removed","public_frontend_registered","generic_initialize_result_serializer")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",required=True,type=Path)
    for name in ("hepta","reference-zip","output"):p.add_argument("--"+name,type=Path)
    p.add_argument("--check-only",action="store_true");a=p.parse_args()
    source=a.source.resolve(strict=True);checked=check(source)
    if a.check_only:
        print(json.dumps(checked,sort_keys=True));return
    if os.environ.get("GITHUB_ACTIONS")!="true":
        raise SystemExit("Fresh owner compilation and capture execute only in GitHub CI.")
    if any(getattr(a,n) is None for n in ("hepta","reference_zip","output")):
        raise ValueError("--hepta, --reference-zip and --output are required")
    hepta=a.hepta.resolve(strict=True);archive=a.reference_zip.resolve(strict=True)
    output=a.output.absolute();output.mkdir(parents=True,exist_ok=False)
    (output/"processes").mkdir()
    report=dict(schema="hepta.current-get-info.recipe.v1",status="RUNNING",
        source_manifest=checked["source_manifest"],processes=[],new_rust_executed=False,
        actual_target_get_info_compared=False,native_calls=0,get_info_cases=0,
        **{name:False for name in FALSE_FLAGS})
    started=time.monotonic()
    def checkpoint():
        report["elapsed_seconds"]=time.monotonic()-started
        save(output/"RECIPE.json",report)
    def execute(label,script,args):
        command=[sys.executable,"-I","-B",str(source/"scripts"/script),*map(str,args)]
        begin=time.monotonic()
        stdout=output/"processes"/(label+".stdout");stderr=output/"processes"/(label+".stderr")
        with stdout.open("xb") as out,stderr.open("xb") as err:
            process=subprocess.Popen(command,stdout=out,stderr=err)
            code=process.wait()
        row=dict(label=label,command=command,exit_code=code,outer_timeout_seconds=None,
            elapsed_seconds=time.monotonic()-begin,
            stdout=dict(bytes=stdout.stat().st_size,sha256=sha(stdout.read_bytes())),
            stderr=dict(bytes=stderr.stat().st_size,sha256=sha(stderr.read_bytes())))
        report["processes"].append(row);checkpoint()
        if code!=0:raise ValueError("recorded stage failed: "+label)
    checkpoint()
    try:
        execute("primary-sources","prepare_reference.py",["--reference-zip",archive,"--output",output/"primary"])
        execute("generate-fixed-owner","generate_guarded.py",["--source",source,"--primary",output/"primary",
            "--hepta",hepta,"--output",output/"generated"])
        execute("fresh-hia-owner","build_owner.py",["--source",source,"--generated",output/"generated",
            "--hepta",hepta,"--output",output/"native"])
        execute("capture-nine","capture_native.py",["--source",source,"--build",output/"native",
            "--output",output/"native-capture"])
        # This is the first phase that decodes the original get_info outputs.
        from verify import verify
        compared=verify(source,output,archive)
        save(output/"READBACK.json",compared)
        report.update(status="PASS",actual_target_get_info_compared=True,native_calls=18,get_info_cases=9,
            owner_source_sha256=compared["owner_source_sha256"],owner_image_sha256=compared["owner_image_sha256"])
    except BaseException as error:
        report.update(status="FAIL",error=repr(error));raise
    finally:checkpoint()
    print(json.dumps({key:value for key,value in report.items() if key!="processes"},sort_keys=True))
if __name__=="__main__":main()
