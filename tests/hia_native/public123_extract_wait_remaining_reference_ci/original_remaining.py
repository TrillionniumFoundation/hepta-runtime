"""Capture only the twenty not-yet-executed original WAIT cases; no native execution."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess,sys,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument("mode",choices=("restore","capture"))
for name in ("source","inputs","output"):p.add_argument("--"+name,type=Path,required=True)
p.add_argument("--domain",required=True)
a=p.parse_args();source=a.source.resolve(strict=True);inputs=a.inputs.absolute();out=a.output.absolute()
sys.path[:0]=[str(source),str(source/"build_reader")]
import archive_stream,callable_common,read_capture,read_only_guard as guard,wait_domain
from restore_graph import download
from run import invoke
from capture_common import file_pin
def put(p,x):p.write_text(json.dumps(x,sort_keys=True,indent=2)+"\n")
identity=json.loads((HERE/"IDENTITY.json").read_bytes())
assert os.environ.get("GITHUB_ACTIONS")=="true" and a.domain in identity["new_domains"]
assert file_pin(source/"SOURCE_MANIFEST.json")==identity["source_manifest"]
admission=callable_common.syntax(source)
if a.mode=="restore":
    assert not inputs.exists();inputs.mkdir(parents=True)
    original=json.loads((source/"INPUTS.json").read_bytes())["original"]
    archive=inputs/"original.zip";download(archive,original["artifact"])
    put(inputs/"ORIGINAL_ARCHIVE_READ.json",archive_stream.archive(archive,original,lambda name:True,output=inputs/"original"))
    cmd=[sys.executable,"-I","-S","-B",str(source/"original_read.py"),"--capture",str(inputs/"original")]
    with (inputs/"reader.stdout").open("xb") as stdout,(inputs/"reader.stderr").open("xb") as stderr:
        child=subprocess.run(cmd,stdout=stdout,stderr=stderr)
    put(inputs/"ORIGINAL_READER_PROCESS.json",{"command":cmd,"exit_code":child.returncode,"stdout":file_pin(inputs/"reader.stdout"),"stderr":file_pin(inputs/"reader.stderr"),"application_executions":0})
    assert child.returncode==0 and not (inputs/"reader.stderr").read_bytes()
    checked=json.loads((inputs/"reader.stdout").read_bytes())
    assert len(checked["probes"])==11 and checked["before"]==checked["after"]
    row=checked["evidence"]["original"]["binaries"]["hepta-batch-sdk-current-original-oracle"]
    binary=inputs/"original/original"/row["path"]
    assert file_pin(binary)==identity["original_binary"]=={k:row[k] for k in ("bytes","sha256")}
    result={"status":"EXACT_ALREADY_BUILT_ORIGINAL_READY","original":{"path":str(binary),**file_pin(binary)},"application_executions":0,"source":original["source"]}
    put(inputs/"BINARY.json",result);print(json.dumps(result,sort_keys=True))
else:
    assert not out.exists();out.mkdir(parents=True)
    put(out/"SOURCE.json",admission);shutil.copytree(HERE,out/"recipe-extension")
    binary=json.loads((inputs/"BINARY.json").read_bytes());assert binary["status"]=="EXACT_ALREADY_BUILT_ORIGINAL_READY"
    put(out/"INPUTS_READY.json",binary)
    for name in ("ORIGINAL_ARCHIVE_READ.json","ORIGINAL_READER_PROCESS.json","reader.stdout","reader.stderr"):(out/name).write_bytes((inputs/name).read_bytes())
    work=Path("/tmp")/("hia-extract-contention-"+a.domain)/"work"
    put(out/"FROZEN_DOMAIN.json",wait_domain.domain(a.domain,work))
    status={"status":"RUNNING","domain":a.domain,"native_executions":0,"old_domains_replayed":False,"first_four_original_cases_replayed":False,"production_installed":False,"full_runtime":False,"full_sdk":False}
    put(out/"RUN.json",status)
    try:
        invoke(out,"original",[sys.executable,"-I","-S","-B",str(source/"capture.py"),"--binary",binary["original"]["path"],"--output",str(out/"original"),"--work",str(work),"--domain",a.domain,"--side","original"],limit=180)
        def read():
            values=read_capture.read(out/"original","original",identity["original_binary"])
            return {"status":"COMPLETE_NEW_ORIGINAL_FOUR_CASES_READ_PASS","cases":[{"name":x["name"],"stdout":read_capture.pin(x["stdout"]),"stderr":read_capture.pin(x["stderr"]),"exit_code":x["exit_code"],"milestones":x["milestones"],"final":x["trace"]["final"]} for x in values],"application_executions":0}
        checked=guard.guarded(read,roots=[out,source,HERE],foreign_path=Path("/dev/null"))
        put(out/"READ_ONLY.json",checked);status.update(status="COMPLETE_NEW_ORIGINAL_WAIT_REFERENCE_CAPTURED",cases=4)
    except BaseException as error:
        status.update(status="FAIL",error=repr(error),traceback=traceback.format_exc())
        if (out/"original.stderr").is_file():sys.stderr.buffer.write((out/"original.stderr").read_bytes());sys.stderr.buffer.flush()
        raise
    finally:put(out/"RUN.json",status)
    print(json.dumps(status,sort_keys=True))
