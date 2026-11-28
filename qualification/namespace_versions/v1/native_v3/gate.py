"""Fresh native custody compilation and packing only; no namespace application invocation."""
import argparse,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,require
from process import Recorder,environment
def run(hepta,output):
    output.mkdir(parents=True,exist_ok=False);identity=source()
    for path in ROOT.rglob("*.py"):compile(read(path),str(path),"exec")
    env,binding=environment(os.environ);r=Recorder(ROOT,output/"processes",env);python=Path(sys.executable).resolve(strict=True)
    try:
        r.run("dependencies",[python,"-I","-B",ROOT/"build.py","--phase","dependencies","--hepta",hepta,"--output",output/"build"],timeout=900)
        r.run("author",[python,"-I","-B",ROOT/"authoring/author_callable.py","--root",ROOT,
            "--hepta",hepta,"--build",output/"build","--output",output/"authored"],timeout=60)
        r.run("build",[python,"-I","-B",ROOT/"build.py","--phase","packer","--hepta",hepta,
            "--authored",output/"authored","--output",output/"build"],timeout=900)
        raw,row=r.run("read",[python,"-I","-B",ROOT/"read_build.py","--build",output/"build",
            "--authored",output/"authored","--output",output/"GUARDED.json"],timeout=180)
        require(source()==identity,"all source unchanged")
        result=loads(raw);result.update(status="NAMESPACE_VERSIONS_CALLABLE_BUILD_PASS",processes=r.records,
            environment=binding,native_application_calls=0,original_application_calls=0)
        (output/"GATE.json").write_bytes(encoded(result))
        for name in("native/namespace_versions_callable.hepta","native/namespace_versions_callable.composition.json","authoring/namespace_versions_callable.S"):
            raw=read(output/"authored/generated"/name);print("GENERATED_FILE_BEGIN "+name)
            print(raw.decode(),end="");print("GENERATED_FILE_END "+name)
        print("NAMESPACE_VERSIONS_CALLABLE_GATE_BEGIN");print(encoded(result).decode(),end="");print("NAMESPACE_VERSIONS_CALLABLE_GATE_END")
    finally:
        for row in r.records:
            path=output/"processes"/row["stderr"]["file"]
            if path.is_file()and path.stat().st_size:sys.stderr.buffer.write(read(path))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.hepta.resolve(strict=True),a.output.absolute())
