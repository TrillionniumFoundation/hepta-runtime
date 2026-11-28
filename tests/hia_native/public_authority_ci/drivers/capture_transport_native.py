"""Capture the actual owned public91 process for all ordinary async framing inputs."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,signal,subprocess,sys,time
sys.dont_write_bytecode=True
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def packed(path,raw):
    data=gzip.compress(raw,mtime=0)
    path.write_bytes(data)
    return dict(path=path.name,**pin(raw),compressed_bytes=len(data),compressed_sha256=sha(data))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("build","cases","output"):p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args();build=a.build.resolve(strict=True);cases=a.cases.resolve(strict=True);out=a.output.absolute()
    built=json.loads((build/"BUILD.json").read_bytes());assert built["status"]=="NATIVE_BUILD_PASS" and built["physical_images"]==91
    manifest=Path(built["manifest"]).resolve(strict=True);raw=manifest.read_bytes();assert sha(raw)==built["manifest_sha256"]
    md=json.loads(raw);binary=manifest.parent/md["elf"]
    assert sha(binary.read_bytes())==built["elf_sha256"]==md["elf_sha256"]
    corpus=json.loads((cases/"cases/manifest.json").read_bytes())
    assert corpus["selected_modes"]==["async","codec-eof"]
    out.mkdir(parents=True,exist_ok=False);started=time.monotonic()
    result=dict(schema="hepta.public-serial-transport.native-capture.v1",status="RUNNING",
        source_driver_sha256=sha(Path(__file__).read_bytes()),manifest_sha256=sha(raw),
        elf_sha256=md["elf_sha256"],corpus_manifest_sha256=sha((cases/"cases/manifest.json").read_bytes()),
        physical_images=91,completed_cases=0,rows=[],actual_target_transport_compared=False,
        original_rust_executed=False,full_sdk_qualified=False,full_async_runtime_qualified=False,
        public_codec_implemented=False,production_activated=False,old_path_removed=False)
    def checkpoint():result["elapsed_seconds"]=time.monotonic()-started;save(out/"SUMMARY.json",result)
    checkpoint()
    try:
        for case in corpus["cases"]:
            if case["mode"]!="async":continue
            wire=(cases/case["input_file"]).read_bytes()
            assert pin(wire)==dict(bytes=case["input_bytes"],sha256=case["input_sha256"])
            folder=out/case["label"];folder.mkdir();(folder/"cwd").mkdir()
            begin=time.monotonic();timed=False
            process=subprocess.Popen([str(binary)],cwd=folder/"cwd",env={"PATH":"","LC_ALL":"C"},
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:stdout,stderr=process.communicate(wire,timeout=60)
            except subprocess.TimeoutExpired:
                timed=True;os.killpg(process.pid,signal.SIGKILL);stdout,stderr=process.communicate()
            row=dict(label=case["label"],mode="async",exit_code=process.returncode,timed_out=timed,
                deadline_seconds=60,elapsed_seconds=time.monotonic()-begin,
                environment={"PATH":"","LC_ALL":"C"},stdin=packed(folder/"stdin.bin.gz",wire),
                stdout=packed(folder/"stdout.bin.gz",stdout),stderr=packed(folder/"stderr.bin.gz",stderr),
                cwd_entries=[p.relative_to(folder/"cwd").as_posix() for p in sorted((folder/"cwd").rglob("*"))],
                write_segmentation="owned subprocess.communicate; OS pipe chunks",
                target_reference_read=False,original_rust_executed=False)
            save(folder/"PROCESS.json",row)
            result["rows"].append(dict(label=case["label"],folder=folder.name,process_sha256=sha((folder/"PROCESS.json").read_bytes()),
                                      stdout_bytes=len(stdout),stdout_sha256=sha(stdout),response_lines=len(stdout.splitlines())))
            result["completed_cases"]+=1;checkpoint()
            assert process.returncode==0 and not timed and not stderr and row["cwd_entries"]==[],case["label"]
        assert result["completed_cases"]==24
        result["status"]="NATIVE_CAPTURE_COMPLETE"
    except BaseException as exc:result.update(status="FAIL",error=repr(exc));raise
    finally:checkpoint()
    print(json.dumps({k:v for k,v in result.items() if k!="rows"},sort_keys=True))
if __name__=="__main__":main()
